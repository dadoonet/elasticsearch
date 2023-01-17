/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.esql.plugin;

import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.support.IndicesOptions;
import org.elasticsearch.client.internal.node.NodeClient;
import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.util.BigArrays;
import org.elasticsearch.common.util.concurrent.CountDown;
import org.elasticsearch.compute.data.Page;
import org.elasticsearch.compute.operator.Driver;
import org.elasticsearch.compute.operator.DriverRunner;
import org.elasticsearch.core.IOUtils;
import org.elasticsearch.core.Releasables;
import org.elasticsearch.index.Index;
import org.elasticsearch.index.IndexService;
import org.elasticsearch.index.shard.IndexShard;
import org.elasticsearch.logging.LogManager;
import org.elasticsearch.logging.Logger;
import org.elasticsearch.search.SearchService;
import org.elasticsearch.search.internal.AliasFilter;
import org.elasticsearch.search.internal.SearchContext;
import org.elasticsearch.search.internal.ShardSearchRequest;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.tasks.TaskId;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.xpack.esql.plan.physical.EsQueryExec;
import org.elasticsearch.xpack.esql.plan.physical.OutputExec;
import org.elasticsearch.xpack.esql.plan.physical.PhysicalPlan;
import org.elasticsearch.xpack.esql.planner.LocalExecutionPlanner;
import org.elasticsearch.xpack.esql.session.EsqlConfiguration;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Computes the result of a {@link PhysicalPlan}.
 */
public class ComputeService {
    private static final Logger LOGGER = LogManager.getLogger(ComputeService.class);
    private final SearchService searchService;
    private final IndexNameExpressionResolver indexNameExpressionResolver;
    private final ClusterService clusterService;
    private final NodeClient client;
    private final ThreadPool threadPool;
    private final BigArrays bigArrays;

    public ComputeService(
        SearchService searchService,
        IndexNameExpressionResolver indexNameExpressionResolver,
        ClusterService clusterService,
        NodeClient client,
        ThreadPool threadPool,
        BigArrays bigArrays
    ) {
        this.searchService = searchService;
        this.indexNameExpressionResolver = indexNameExpressionResolver;
        this.clusterService = clusterService;
        this.client = client;
        this.threadPool = threadPool;
        this.bigArrays = bigArrays.withCircuitBreaking();
    }

    private void acquireSearchContexts(String[] indexNames, ActionListener<List<SearchContext>> listener) {
        try {
            Index[] indices = indexNameExpressionResolver.concreteIndices(
                clusterService.state(),
                IndicesOptions.STRICT_EXPAND_OPEN,
                indexNames
            );
            List<IndexShard> targetShards = new ArrayList<>();
            for (Index index : indices) {
                IndexService indexService = searchService.getIndicesService().indexServiceSafe(index);
                for (IndexShard indexShard : indexService) {
                    targetShards.add(indexShard);
                }
            }
            if (targetShards.isEmpty()) {
                listener.onResponse(List.of());
                return;
            }
            CountDown countDown = new CountDown(targetShards.size());
            for (IndexShard targetShard : targetShards) {
                targetShard.awaitShardSearchActive(ignored -> {
                    if (countDown.countDown()) {
                        ActionListener.completeWith(listener, () -> {
                            final List<SearchContext> searchContexts = new ArrayList<>();
                            boolean success = false;
                            try {
                                for (IndexShard shard : targetShards) {
                                    ShardSearchRequest shardSearchLocalRequest = new ShardSearchRequest(
                                        shard.shardId(),
                                        0,
                                        AliasFilter.EMPTY
                                    );
                                    SearchContext context = searchService.createSearchContext(
                                        shardSearchLocalRequest,
                                        SearchService.NO_TIMEOUT
                                    );
                                    searchContexts.add(context);
                                }
                                for (SearchContext searchContext : searchContexts) {
                                    searchContext.preProcess();
                                }
                                success = true;
                                return searchContexts;
                            } finally {
                                if (success == false) {
                                    IOUtils.close(searchContexts);
                                }
                            }
                        });
                    }
                });
            }
        } catch (Exception e) {
            listener.onFailure(e);
        }
    }

    public void runCompute(Task rootTask, PhysicalPlan physicalPlan, EsqlConfiguration configuration, ActionListener<List<Page>> listener) {
        String[] indexNames = physicalPlan.collect(l -> l instanceof EsQueryExec)
            .stream()
            .map(qe -> ((EsQueryExec) qe).index().name())
            .collect(Collectors.toSet())
            .toArray(String[]::new);

        acquireSearchContexts(indexNames, ActionListener.wrap(searchContexts -> {
            boolean success = false;
            List<Driver> drivers = new ArrayList<>();
            Runnable release = () -> Releasables.close(() -> Releasables.close(searchContexts), () -> Releasables.close(drivers));
            try {
                LocalExecutionPlanner planner = new LocalExecutionPlanner(bigArrays, configuration, searchContexts);
                List<Page> collectedPages = Collections.synchronizedList(new ArrayList<>());
                LocalExecutionPlanner.LocalExecutionPlan localExecutionPlan = planner.plan(
                    new OutputExec(physicalPlan, (l, p) -> { collectedPages.add(p); })
                );  // TODO it's more normal to collect a result per thread and merge in the callback
                LOGGER.info("Local execution plan:\n{}", localExecutionPlan.describe());
                drivers.addAll(localExecutionPlan.createDrivers());
                if (drivers.isEmpty()) {
                    throw new IllegalStateException("no drivers created");
                }
                LOGGER.info("using {} drivers", drivers.size());

                TaskId parentTask = rootTask.taskInfo(client.getLocalNodeId(), false).taskId();

                new DriverRunner() {
                    @Override
                    protected void start(Driver driver, ActionListener<Void> done) {
                        EsqlComputeEngineAction.Request request = new EsqlComputeEngineAction.Request(indexNames, driver);
                        request.setParentTask(parentTask);
                        client.executeLocally(
                            EsqlComputeEngineAction.INSTANCE,
                            request,
                            ActionListener.wrap(r -> done.onResponse(null), done::onFailure)
                        );
                    }
                }.runToCompletion(drivers, new ActionListener<>() {
                    @Override
                    public void onResponse(List<Driver.Result> results) {
                        release.run();
                        Exception e = Driver.Result.collectFailures(results);
                        if (e != null) {
                            listener.onFailure(e);
                        } else {
                            listener.onResponse(collectedPages);
                        }
                    }

                    @Override
                    public void onFailure(Exception e) {
                        release.run();
                        listener.onFailure(e);
                    }
                });
                success = true;
            } finally {
                if (success == false) {
                    release.run();
                }
            }
        }, listener::onFailure));
    }
}

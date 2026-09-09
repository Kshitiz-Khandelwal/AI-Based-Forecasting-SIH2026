import { NextResponse } from "next/server";
import { access, readFile } from "node:fs/promises";
import path from "node:path";

type Evaluation = {
  dataset?: string;
  split?: string;
  sequence_grouping?: string;
  evaluation?: unknown;
  status?: string;
  invalidation_reason?: string;
};

type BenchmarkResults = {
  dataset?: string;
  split?: string;
  model_artifact?: string;
  logistic_regression?: unknown;
  temporal_gru?: unknown;
  majority_collapse_summary?: unknown;
};

const DEFAULT_EVAL_ARTIFACT = "temporal_gru_forecaster_grouped_v5_evaluation.json";

function getArtifactPaths() {
  const evalFilename = process.env.FORECASTING_EVAL_ARTIFACT || DEFAULT_EVAL_ARTIFACT;
  const modelsDir = path.resolve(process.cwd(), "..", "services/forecasting_engine/models");
  const evalPath = path.join(modelsDir, evalFilename);

  // Derive model artifact binary name (e.g., temporal_gru_forecaster_grouped_v5.pt)
  const modelArtifact = evalFilename.replace("_evaluation.json", ".pt");

  // Derive sibling benchmark results filename
  const benchmarkFilename = evalFilename.replace("_evaluation.json", "_benchmark_results.json");
  const benchmarkPath = path.join(modelsDir, benchmarkFilename);

  return { evalPath, benchmarkPath, evalFilename, modelArtifact };
}

/**
 * Serves the latest certified grouped holdout evaluation report and baseline comparison.
 * Configurable via FORECASTING_EVAL_ARTIFACT (defaults to v5 certified leak-free).
 */
export async function GET() {
  const { evalPath, benchmarkPath, modelArtifact } = getArtifactPaths();

  try {
    await access(evalPath);
    const report = JSON.parse(await readFile(evalPath, "utf8")) as Evaluation;

    if (!report.evaluation || !report.sequence_grouping) {
      throw new Error("The grouped evaluation report does not contain required fields.");
    }

    // Attempt to load sibling benchmark results for LR vs GRU comparison if present
    let baselineComparison = null;
    try {
      await access(benchmarkPath);
      const benchmark = JSON.parse(await readFile(benchmarkPath, "utf8")) as BenchmarkResults;
      baselineComparison = {
        logisticRegression: benchmark.logistic_regression ?? null,
        temporalGru: benchmark.temporal_gru ?? null,
        collapseSummary: benchmark.majority_collapse_summary ?? null,
      };
    } catch {
      // Sibling benchmark is optional
    }

    return NextResponse.json({
      available: true,
      source: "persisted grouped holdout evaluation",
      modelArtifact,
      split: report.split,
      sequenceGrouping: report.sequence_grouping,
      deploymentStatus: "Experimental — not deployed",
      status: report.status ?? "certified_leak_free",
      metrics: report.evaluation,
      baselineComparison,
    });
  } catch (error) {
    return NextResponse.json({
      available: false,
      message: `No grouped-sequence evaluation report found at ${path.basename(evalPath)}. Run and persist a corrected benchmark before presenting model metrics.`,
      error: error instanceof Error ? error.message : String(error),
    });
  }
}

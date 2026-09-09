import { NextResponse } from "next/server";
import { access, readFile } from "node:fs/promises";
import path from "node:path";

type Evaluation = {
  dataset?: string;
  split?: string;
  sequence_grouping?: string;
  evaluation?: unknown;
};

const GROUPED_EVALUATION = path.resolve(
  process.cwd(),
  "..",
  "services/forecasting_engine/models/temporal_gru_forecaster_grouped_v2_evaluation.json",
);

/**
 * The grouped evaluation is intentionally the only report surfaced here. Older
 * flattened-window results are not comparable after the sequence-boundary fix.
 */
export async function GET() {
  try {
    await access(GROUPED_EVALUATION);
    const report = JSON.parse(await readFile(GROUPED_EVALUATION, "utf8")) as Evaluation;

    if (!report.evaluation || !report.sequence_grouping) {
      throw new Error("The grouped evaluation report does not contain required fields.");
    }

    return NextResponse.json({
      available: true,
      source: "persisted grouped holdout evaluation",
      modelArtifact: "temporal_gru_forecaster_grouped_v2.pt",
      split: report.split,
      sequenceGrouping: report.sequence_grouping,
      deploymentStatus: "Experimental — not deployed",
      metrics: report.evaluation,
    });
  } catch {
    return NextResponse.json({
      available: false,
      message: "No grouped-sequence evaluation report is available in this deployment. Run and persist a corrected benchmark before presenting model metrics.",
    });
  }
}

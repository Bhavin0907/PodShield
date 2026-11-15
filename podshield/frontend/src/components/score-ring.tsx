import { useEffect, useState } from "react";

import type { Grade } from "@/lib/api";
import { GRADE_COLOR } from "@/lib/constants";
import { cn } from "@/lib/utils";

interface ScoreRingProps {
  score: number | null;
  grade: Grade | null;
  size?: number;
  strokeWidth?: number;
  showGrade?: boolean;
  className?: string;
}

export function ScoreRing({ score, grade, size = 120, strokeWidth, showGrade = false, className }: ScoreRingProps) {
  const stroke = strokeWidth ?? Math.max(4, Math.round(size / 11));
  const radius = (size - stroke) / 2;
  const circumference = 2 * Math.PI * radius;
  const target = score === null ? 0 : Math.min(100, Math.max(0, score));
  const color = grade ? GRADE_COLOR[grade] : "#71717a";

  // Animate from empty to the score on mount.
  const [shown, setShown] = useState(0);
  useEffect(() => {
    const id = requestAnimationFrame(() => setShown(target));
    return () => cancelAnimationFrame(id);
  }, [target]);

  return (
    <div
      className={cn("relative shrink-0", className)}
      style={{ width: size, height: size }}
      role="img"
      aria-label={score === null ? "Not scored" : `Score ${score} out of 100${grade ? `, grade ${grade}` : ""}`}
    >
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={radius} fill="none" strokeWidth={stroke} className="stroke-muted" />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          strokeWidth={stroke}
          strokeLinecap="round"
          stroke={color}
          strokeDasharray={circumference}
          strokeDashoffset={circumference * (1 - shown / 100)}
          style={{ transition: "stroke-dashoffset 900ms cubic-bezier(0.22, 1, 0.36, 1)", filter: `drop-shadow(0 0 6px ${color}55)` }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center leading-none">
        <span className="font-semibold tabular-nums" style={{ fontSize: size * 0.3 }}>
          {score === null ? "-" : score}
        </span>
        {showGrade && grade ? (
          <span className="mt-1 font-bold" style={{ fontSize: size * 0.14, color }}>
            Grade {grade}
          </span>
        ) : (
          size >= 90 && (
            <span className="mt-1 text-muted-foreground" style={{ fontSize: size * 0.1 }}>
              / 100
            </span>
          )
        )}
      </div>
    </div>
  );
}

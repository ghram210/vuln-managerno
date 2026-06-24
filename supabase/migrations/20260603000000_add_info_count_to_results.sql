-- Add info_count to scan_results to accurately track informational findings
ALTER TABLE public.scan_results ADD COLUMN IF NOT EXISTS info_count INTEGER NOT NULL DEFAULT 0;

-- Update existing records to calculate info_count as the remainder (for backward compatibility)
UPDATE public.scan_results
SET info_count = GREATEST(0, total_findings - (critical_count + high_count + medium_count + low_count))
WHERE info_count = 0 AND total_findings > 0;

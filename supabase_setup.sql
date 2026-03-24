-- PhishGuard - Supabase 테이블 설정
-- Supabase Dashboard > SQL Editor에서 실행하세요.

CREATE TABLE IF NOT EXISTS history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    category TEXT NOT NULL,
    title TEXT NOT NULL,
    data JSONB NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_history_category ON history(category);
CREATE INDEX IF NOT EXISTS idx_history_created_at ON history(created_at DESC);

-- RLS 활성화 (service key 사용 시 모든 작업 허용)
ALTER TABLE history ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Allow all operations" ON history
    FOR ALL
    USING (true)
    WITH CHECK (true);

-- PhishGuard - Supabase 테이블 설정
-- Supabase Dashboard > SQL Editor에서 실행하세요.

CREATE TABLE IF NOT EXISTS history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    category TEXT NOT NULL,
    seq INTEGER NOT NULL DEFAULT 0,
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

-- 키워드 모니터링: 등록 키워드
CREATE TABLE IF NOT EXISTS keywords (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    keyword TEXT NOT NULL UNIQUE,
    is_active BOOLEAN DEFAULT true,
    last_searched_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_keywords_active ON keywords(is_active) WHERE is_active = true;

ALTER TABLE keywords ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Allow all operations" ON keywords
    FOR ALL
    USING (true)
    WITH CHECK (true);

-- 키워드 모니터링: 검색 결과
CREATE TABLE IF NOT EXISTS keyword_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    keyword_id UUID NOT NULL REFERENCES keywords(id) ON DELETE CASCADE,
    keyword TEXT NOT NULL,
    source TEXT NOT NULL,
    total_found INTEGER DEFAULT 0,
    results JSONB NOT NULL DEFAULT '[]'::jsonb,
    searched_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_keyword_results_keyword_id ON keyword_results(keyword_id);
CREATE INDEX IF NOT EXISTS idx_keyword_results_searched_at ON keyword_results(searched_at DESC);

ALTER TABLE keyword_results ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Allow all operations" ON keyword_results
    FOR ALL
    USING (true)
    WITH CHECK (true);

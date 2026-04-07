const express = require('express');
const router = express.Router();
const File = require('../models/file');
const Course = require('../models/course');
const User = require('../models/userData');
const SavedSearch = require('../models/SavedSearch');
const authenticateJWT_user = require('./authentication/jwtAuth');

// Import advanced search services
const semanticSearch = require('../services/semanticSearchService');
const nlpService = require('../services/nlpService');
const spellCorrection = require('../services/spellCorrectionService');

// ============================================================================
// STARTUP: Ensure text indices exist (called ONCE at module load, not per-request)
// ============================================================================
let indicesEnsured = false;
async function ensureTextIndices() {
  if (indicesEnsured) return;
  try {
    await Promise.all([
      File.collection.createIndex(
        { filename: 'text', filedescription: 'text', category: 'text' },
        { weights: { filename: 10, category: 5, filedescription: 1 }, name: 'file_text_search' }
      ),
      Course.collection.createIndex(
        { title: 'text', description: 'text', category: 'text' },
        { weights: { title: 10, category: 5, description: 1 }, name: 'course_text_search' }
      )
    ]);
    indicesEnsured = true;
    console.log('✅ Text indices ready');
  } catch (err) {
    // Indices already exist — mark as done anyway
    indicesEnsured = true;
    console.log('📚 Text indices already exist:', err.message);
  }
}
ensureTextIndices(); // Fire immediately on module load

// ============================================================================
// HELPER: Levenshtein distance for fuzzy matching
// ============================================================================
function levenshteinDistance(a, b) {
  const m = a.length, n = b.length;
  const dp = Array.from({ length: m + 1 }, (_, i) =>
    Array.from({ length: n + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0))
  );
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = a[i - 1] === b[j - 1]
        ? dp[i - 1][j - 1]
        : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    }
  }
  return dp[m][n];
}

function fuzzyMatch(query, text, threshold = 0.7) {
  const q = query.toLowerCase().trim();
  const t = text.toLowerCase().trim();
  if (!q || !t) return 0;
  if (t.includes(q)) return 1; // substring is always a match
  const distance = levenshteinDistance(q, t);
  const similarity = 1 - distance / Math.max(q.length, t.length);
  return similarity >= threshold ? similarity : 0;
}

// ============================================================================
// HELPER: Build CloudFront preview URL for files
// ============================================================================
const CF_DOMAIN = (process.env.CF_DOMAIN_PROFILES_COURSES || 'https://d3epchi0htsp3c.cloudfront.net')
  .replace(/^https?:\/\//, '')
  .replace(/\/$/, '');

function buildPreviewUrl(file) {
  if (file.previewUrl && file.previewUrl.trim()) return file.previewUrl;
  if (file.imageType) {
    const ext = file.imageType.toLowerCase() === 'jpeg' ? 'jpg' : file.imageType.toLowerCase();
    return `https://${CF_DOMAIN}/files-previews/images/${file._id}.${ext}`;
  }
  return null;
}

// ============================================================================
// HELPER: Normalise a raw value safely
// ============================================================================
function safeFloat(val, fallback = 0) {
  const n = parseFloat(val);
  return isNaN(n) ? fallback : n;
}

// ============================================================================
// HELPER: Extract search intent and context
// ============================================================================
const INTENT_MAP = {
  learning:       ['learn', 'tutorial', 'course', 'class', 'training', 'education'],
  reference:      ['guide', 'manual', 'documentation', 'reference', 'pdf', 'ebook'],
  certification:  ['certificate', 'certification', 'exam', 'test', 'preparation'],
  project:        ['project', 'example', 'sample', 'template', 'starter'],
  debugging:      ['fix', 'error', 'bug', 'debug', 'troubleshoot', 'solution'],
  specialization: ['advanced', 'pro', 'expert', 'master', 'professional'],
};

function analyzeSearchContext(query) {
  const lower = query.toLowerCase();
  const keywords = lower.split(/\s+/).filter(Boolean);
  const intents = Object.entries(INTENT_MAP)
    .filter(([, words]) => words.some(w => lower.includes(w)))
    .map(([intent]) => intent);

  return {
    keywords,
    intents: intents.length > 0 ? intents : ['general'],
    isSpecific: keywords.length > 2,
    hasSpecialChars: /[^\w\s]/.test(query),
    length: keywords.length,
  };
}

// ============================================================================
// HELPER: Multi-field weighted relevance score
// ============================================================================
function calculateCombinedWeightedScore(item, query) {
  const queryLower = query.toLowerCase().trim();
  const queryWords = queryLower.split(/\s+/).filter(w => w.length > 0);
  if (queryWords.length === 0) {
    return (item.rating || 0) * 10 + Math.min((item.downloadCount || item.enrollCount || 0) / 50, 30);
  }

  let total = 0;

  // --- Title (weight 100) ---
  const title = (item.filename || item.title || '').toLowerCase();
  let titleScore = 0;
  if (title === queryLower)                      titleScore = 100;
  else if (title.startsWith(queryLower))         titleScore = 90;
  else if (title.includes(queryLower))           titleScore = 75;
  else {
    const wordHits = queryWords.filter(w => title.includes(w)).length;
    titleScore = (wordHits / queryWords.length) * 60;
    const fuzzy = fuzzyMatch(queryLower, title, 0.5);
    if (fuzzy > 0) titleScore = Math.max(titleScore, fuzzy * 50);
  }
  total += titleScore * 100;

  // --- Description (weight 60) ---
  const desc = (item.filedescription || item.description || '').toLowerCase();
  if (desc.length > 0) {
    let descScore = 0;
    if (desc.includes(queryLower)) descScore = 70;
    else {
      const hits = queryWords.filter(w => desc.includes(w)).length;
      descScore = (hits / queryWords.length) * 50;
    }
    total += descScore * 60;
  }

  // --- Category (weight 40) ---
  const cat = (item.category || '').toLowerCase();
  let catScore = 0;
  if (cat.includes(queryLower)) catScore = 80;
  else {
    const hits = queryWords.filter(w => cat.includes(w)).length;
    catScore = (hits / queryWords.length) * 60;
  }
  total += catScore * 40;

  // --- Author (weight 30) ---
  const author = (typeof item.creator === 'string' ? item.creator : item.creatorName || '').toLowerCase();
  if (author && author.includes(queryLower)) total += 60 * 30;

  // --- Price relevance (weight 20) ---
  const isFreeQuery = queryWords.includes('free');
  const isPaidQuery = queryWords.includes('paid');
  if (isFreeQuery && (item.price || 0) === 0) total += 50 * 20;
  if (isPaidQuery && (item.price || 0) > 0)   total += 50 * 20;

  // --- Quality boosters ---
  total += (item.rating || 0) * 5;
  total += Math.min((item.downloadCount || item.enrollCount || 0) / 100, 40);

  // --- Recency boost ---
  const daysOld = (Date.now() - new Date(item.createdAt || 0).getTime()) / 86400000;
  if (daysOld <= 7)       total += 30;
  else if (daysOld <= 30) total += 20;
  else if (daysOld <= 90) total += 10;

  return Math.max(0, total);
}

// ============================================================================
// HELPER: Boolean / field-specific query parser
// BUG FIX: regex must be recreated each call to avoid lastIndex drift
// ============================================================================
function parseBooleanQuery(query) {
  // Recreate regex each time — using a stored regex with /g and exec() across calls
  // causes lastIndex to persist and skip matches.
  const fieldRegex = /(title|author|category|price|rating):\s*"([^"]+)"|(\w+):(\w+)/g;
  const fieldSearches = {};
  let cleanQuery = query;

  let match;
  while ((match = fieldRegex.exec(query)) !== null) {
    const field = match[1] || match[3];
    const value = match[2] || match[4];
    if (!fieldSearches[field]) fieldSearches[field] = [];
    fieldSearches[field].push(value);
    cleanQuery = cleanQuery.replace(match[0], '').trim();
  }

  return {
    fieldSearches,
    cleanQuery: cleanQuery.trim(),
    hasAnd: /\bAND\b/i.test(query),
    hasOr:  /\bOR\b/i.test(query),
    hasNot: (query.match(/\bNOT\b/gi) || []).length,
    originalQuery: query,
  };
}

// ============================================================================
// HELPER: Apply field-specific overrides to a Mongoose filter object
// ============================================================================
function applyFieldSpecificFilters(fieldSearches, baseFilter) {
  const q = { ...baseFilter };
  if (fieldSearches.title)    q.filename = { $regex: fieldSearches.title[0], $options: 'i' };
  if (fieldSearches.category) q.category = { $regex: fieldSearches.category[0], $options: 'i' };
  if (fieldSearches.price) {
    const v = parseFloat(fieldSearches.price[0]);
    if (!isNaN(v)) q.price = { $lte: v };
  }
  if (fieldSearches.rating) {
    const v = parseFloat(fieldSearches.rating[0]);
    if (!isNaN(v)) q.rating = { $gte: v };
  }
  return q;
}

// ============================================================================
// HELPER: Deduplicate results by _id
// ============================================================================
function deduplicateById(items) {
  const seen = new Set();
  return items.filter(item => {
    const id = String(item._id);
    if (seen.has(id)) return false;
    seen.add(id);
    return true;
  });
}

// ============================================================================
// HELPER: Format file doc → unified result shape
// ============================================================================
function formatFile(f) {
  return {
    _id: f._id,
    title: f.filename,
    price: f.price,
    rating: f.rating,
    interest: f.downloadCount,
    category: f.category,
    createdAt: f.createdAt,
    image: buildPreviewUrl(f),
    type: 'file',
    creator: f.user,
  };
}

// ============================================================================
// HELPER: Format course doc → unified result shape
// ============================================================================
function formatCourse(c) {
  return {
    _id: c._id,
    title: c.title,
    price: c.price,
    rating: c.rating,
    interest: c.enrollCount,
    category: c.category,
    createdAt: c.createdAt,
    image: c.thumbnailUrl,
    type: 'course',
    creator: c.userId,
  };
}

// ============================================================================
// HELPER: Safe wrapper around external AI services
// Returns a default shape if the service throws or returns unexpected data
// ============================================================================
function safeSpellCorrect(query) {
  try {
    const result = spellCorrection.correctAndExpandQuery(query);
    return {
      correctedQuery: result.correctedQuery || query,
      expandedTerms: Array.isArray(result.expandedTerms) ? result.expandedTerms : [],
      hasTypos: !!result.hasTypos,
      averageConfidence: result.averageConfidence ?? 1,
      corrections: Array.isArray(result.corrections) ? result.corrections : [],
    };
  } catch (e) {
    console.error('⚠️  spellCorrection failed:', e.message);
    return { correctedQuery: query, expandedTerms: [], hasTypos: false, averageConfidence: 1, corrections: [] };
  }
}

function safeNlpParse(query) {
  try {
    return nlpService.parseNaturalLanguageQuery(query);
  } catch (e) {
    console.error('⚠️  nlpService failed:', e.message);
    return { entities: {}, filters: {}, summary: query };
  }
}

function safeSemanticExpand(query) {
  try {
    const expansion = semanticSearch.expandSemanticQuery(query);
    return {
      primaryKeywords: Array.isArray(expansion.primaryKeywords) ? expansion.primaryKeywords : [],
      relatedKeywords: Array.isArray(expansion.relatedKeywords) ? expansion.relatedKeywords : [],
      allKeywords: Array.isArray(expansion.allKeywords) ? expansion.allKeywords : [],
      confidence: expansion.confidence ?? 0,
    };
  } catch (e) {
    console.error('⚠️  semanticSearch.expandSemanticQuery failed:', e.message);
    return { primaryKeywords: [], relatedKeywords: [], allKeywords: [], confidence: 0 };
  }
}

function safeSemanticFilter(query) {
  try {
    return semanticSearch.buildSemanticFilter(query);
  } catch (e) {
    return { suggestedFilters: {}, intents: [] };
  }
}

function safeLearningPath(keyword) {
  try {
    return semanticSearch.getLearningPath(keyword) || [];
  } catch (e) {
    return [];
  }
}

// ============================================================================
// HELPER: Extract faceted counts from a result list
// (removed Math.random() — uses a fixed "Unknown" bucket instead)
// ============================================================================
function extractFacets(items) {
  const facets = { categories: {}, priceRanges: {}, ratingRanges: {}, formats: {} };

  for (const item of items) {
    // Category
    const cat = item.category || 'Uncategorised';
    facets.categories[cat] = (facets.categories[cat] || 0) + 1;

    // Price range
    const pr =
      (item.price || 0) === 0   ? 'Free'
      : item.price <= 500       ? 'Budget (₹0–500)'
      : item.price <= 1500      ? 'Mid-range (₹500–1500)'
      :                           'Premium (₹1500+)';
    facets.priceRanges[pr] = (facets.priceRanges[pr] || 0) + 1;

    // Rating range
    const rr =
      (item.rating || 0) >= 4.5 ? '4.5+ Stars'
      : (item.rating || 0) >= 4  ? '4+ Stars'
      : (item.rating || 0) >= 3  ? '3+ Stars'
      :                             'Below 3 Stars';
    facets.ratingRanges[rr] = (facets.ratingRanges[rr] || 0) + 1;

    // Format (inferred from title)
    const lower = (item.title || '').toLowerCase();
    const fmt =
      lower.includes('video') || lower.includes('mp4') ? 'Video'
      : lower.includes('pdf')                           ? 'PDF'
      : lower.includes('interactive')                   ? 'Interactive'
      : lower.includes('slides')                        ? 'Slides'
      :                                                   'Document';
    facets.formats[fmt] = (facets.formats[fmt] || 0) + 1;
  }

  return facets;
}

function buildDynamicFilters(results) {
  const facets = extractFacets(results);
  const dynamics = {};

  const toSorted = obj =>
    Object.entries(obj).sort((a, b) => b[1] - a[1]).map(([k, count]) => ({ name: k, count }));

  if (Object.keys(facets.categories).length > 1)  dynamics.categories  = toSorted(facets.categories);
  if (Object.keys(facets.priceRanges).length > 1) dynamics.priceRanges = toSorted(facets.priceRanges);
  if (Object.keys(facets.ratingRanges).length > 1) dynamics.ratingRanges = toSorted(facets.ratingRanges);
  if (Object.keys(facets.formats).length > 1)     dynamics.formats     = toSorted(facets.formats);

  dynamics.stats = {
    minPrice:    Math.min(...results.map(r => r.price  || 0)),
    maxPrice:    Math.max(...results.map(r => r.price  || 0)),
    minRating:   Math.min(...results.map(r => r.rating || 0)),
    maxRating:   Math.max(...results.map(r => r.rating || 5)),
    resultCount: results.length,
  };

  return dynamics;
}

// ============================================================================
// HELPER: "Did you mean?" — efficient DB lookup (no full-scan fuzzy in JS)
// Queries the DB for similar titles using a lighter prefix regex approach
// then applies fuzzy scoring only to the small result set.
// ============================================================================
async function generateDidYouMean(query) {
  if (!query || query.length < 3) return null;

  const firstWord = query.split(/\s+/)[0];
  // Grab candidates whose title starts with at least the first 2 chars
  const prefix = firstWord.slice(0, 2);
  const regexPrefix = new RegExp(`^${prefix}`, 'i');

  const [files, courses] = await Promise.all([
    File.find({ filename: regexPrefix }).select('filename').lean().limit(50),
    Course.find({ title: regexPrefix }).select('title').lean().limit(50),
  ]);

  const allTitles = [...files.map(f => f.filename), ...courses.map(c => c.title)];

  const suggestions = allTitles
    .map(title => ({ title, score: fuzzyMatch(query.toLowerCase(), title.toLowerCase(), 0.45) }))
    .filter(x => x.score > 0 && x.title.toLowerCase() !== query.toLowerCase())
    .sort((a, b) => b.score - a.score)
    .slice(0, 3)
    .map(x => x.title);

  return suggestions.length > 0 ? suggestions : null;
}

// ============================================================================
// ROUTE: GET /api/search/advanced
// ============================================================================
router.get('/advanced', async (req, res) => {
  try {
    let {
      q = '',
      category = [],
      priceMin = 0,
      priceMax = 10000,
      minRating = 0,
      sortBy = 'relevance',
      assetType = 'all',
      creator = '',
      dateRange = 'all',
      page = 1,
      limit = 12,
    } = req.query;

    const pageNum  = Math.max(1, parseInt(page)  || 1);
    const limitNum = Math.min(50, Math.max(1, parseInt(limit) || 12)); // cap at 50
    const skip     = (pageNum - 1) * limitNum;

    const categoryArray = Array.isArray(category) ? category : [category].filter(Boolean);
    const priceMinF = safeFloat(priceMin, 0);
    const priceMaxF = safeFloat(priceMax, 10000);
    const minRatingF = safeFloat(minRating, 0);

    // ── Spell correction ──────────────────────────────────────────────────
    const correctionResult = safeSpellCorrect(q);
    const correctedQuery   = correctionResult.correctedQuery;
    const expandedTerms    = correctionResult.expandedTerms;
    console.log(`🔤 Query: "${q}"  →  corrected: "${correctedQuery}"`);

    // ── NLP parsing ───────────────────────────────────────────────────────
    const nlpResult = safeNlpParse(correctedQuery);
    console.log('🧠 NLP entities:', nlpResult.entities);

    // Override price cap if NLP detected one
    const effectivePriceMax = nlpResult.filters?.priceMax
      ? Math.min(priceMaxF, nlpResult.filters.priceMax)
      : priceMaxF;

    // ── Semantic expansion ────────────────────────────────────────────────
    const semanticExpansion = safeSemanticExpand(correctedQuery);
    const semanticFilters   = safeSemanticFilter(correctedQuery);
    console.log('🌐 Semantic keywords:', semanticExpansion.allKeywords.slice(0, 8));

    // ── Date filter ───────────────────────────────────────────────────────
    const DATE_DAYS = { week: 7, month: 30, '3months': 90, '6months': 180, year: 365 };
    const dateFilter = DATE_DAYS[dateRange]
      ? { createdAt: { $gte: new Date(Date.now() - DATE_DAYS[dateRange] * 86400000) } }
      : {};

    // ── Base DB filters ───────────────────────────────────────────────────
    const baseFileFilters = {
      ...(priceMinF > 0 || effectivePriceMax < 10000
        ? { price: { $gte: priceMinF, $lte: effectivePriceMax } }
        : {}),
      ...(minRatingF > 0 ? { rating: { $gte: minRatingF } } : {}),
      ...dateFilter,
      ...(categoryArray.length > 0 ? { category: { $in: categoryArray } } : {}),
    };
    const baseCourseFilters = { ...baseFileFilters };

    // ── Creator filter ────────────────────────────────────────────────────
    if (creator) {
      const creatorUser = await User.findOne({
        $or: [
          { username: new RegExp(creator, 'i') },
          { email: new RegExp(creator, 'i') },
        ],
      }).select('_id').lean();
      if (creatorUser) {
        baseFileFilters.user     = creatorUser._id;
        baseCourseFilters.userId = creatorUser._id;
      }
    }

    // ── Boolean / field-specific query parsing ────────────────────────────
    const boolParsed = parseBooleanQuery(correctedQuery);
    const cleanQuery = boolParsed.cleanQuery || correctedQuery;
    const fileFilters   = applyFieldSpecificFilters(boolParsed.fieldSearches, baseFileFilters);
    const courseFilters = applyFieldSpecificFilters(boolParsed.fieldSearches, baseCourseFilters);

    // ── Tier 1: Exact / semantic keyword matches ───────────────────────────
    let files   = [];
    let courses = [];

    if (cleanQuery.trim()) {
      const extraTerms = [...new Set(expandedTerms.slice(0, 4).filter(t => t && t.length > 2))];

      if (assetType !== 'courses') {
        files = await File.find({
          ...fileFilters,
          $or: [
            { filename:      { $regex: cleanQuery, $options: 'i' } },
            { filedescription: { $regex: cleanQuery, $options: 'i' } },
            { category:      { $regex: cleanQuery, $options: 'i' } },
            ...extraTerms.map(t => ({ filename: { $regex: t, $options: 'i' } })),
          ],
        })
          .select('_id filename price rating downloadCount category createdAt imageType previewUrl user')
          .lean()
          .limit(200);
      }

      if (assetType !== 'files') {
        courses = await Course.find({
          ...courseFilters,
          $or: [
            { title:       { $regex: cleanQuery, $options: 'i' } },
            { description: { $regex: cleanQuery, $options: 'i' } },
            { category:    { $regex: cleanQuery, $options: 'i' } },
            ...extraTerms.map(t => ({ title: { $regex: t, $options: 'i' } })),
          ],
        })
          .select('_id title price rating enrollCount category createdAt thumbnailUrl userId')
          .lean()
          .limit(200);
      }
    }

    // ── Tier 2: Individual keyword fallback ───────────────────────────────
    if (files.length === 0 && courses.length === 0 && cleanQuery.trim()) {
      console.log('⚠️  Tier 1 empty — trying individual keywords');
      const kws = expandedTerms.filter(k => k && k.length > 2);

      if (kws.length > 0) {
        const kwOr = kws.map(kw => ({
          $or: [
            { filename:  { $regex: kw, $options: 'i' } },
            { category:  { $regex: kw, $options: 'i' } },
          ],
        }));
        const ckwOr = kws.map(kw => ({
          $or: [
            { title:       { $regex: kw, $options: 'i' } },
            { description: { $regex: kw, $options: 'i' } },
          ],
        }));

        if (assetType !== 'courses') {
          files = await File.find({ ...fileFilters, $or: kwOr })
            .select('_id filename price rating downloadCount category createdAt imageType previewUrl user')
            .lean().limit(200);
        }
        if (assetType !== 'files') {
          courses = await Course.find({ ...courseFilters, $or: ckwOr })
            .select('_id title price rating enrollCount category createdAt thumbnailUrl userId')
            .lean().limit(200);
        }
      }
    }

    // ── Tier 3: Semantic category fallback ────────────────────────────────
    if (files.length === 0 && courses.length === 0 && semanticExpansion.confidence > 0.5) {
      console.log('🎯 Tier 3 — semantic category fallback');
      const semCats = semanticExpansion.allKeywords;

      if (assetType !== 'courses') {
        files = await File.find({ ...fileFilters, category: { $in: semCats } })
          .select('_id filename price rating downloadCount category createdAt imageType previewUrl user')
          .sort({ rating: -1, downloadCount: -1 }).lean().limit(100);
      }
      if (assetType !== 'files') {
        courses = await Course.find({ ...courseFilters, category: { $in: semCats } })
          .select('_id title price rating enrollCount category createdAt thumbnailUrl userId')
          .sort({ rating: -1, enrollCount: -1 }).lean().limit(100);
      }
    }

    // ── Tier 4: Trending fallback ─────────────────────────────────────────
    const hadZeroResults = files.length === 0 && courses.length === 0;
    if (hadZeroResults) {
      console.log('📈 Tier 4 — trending fallback');
      if (assetType !== 'courses') {
        files = await File.find(fileFilters)
          .select('_id filename price rating downloadCount category createdAt imageType previewUrl user')
          .sort({ downloadCount: -1, rating: -1 }).lean().limit(100);
      }
      if (assetType !== 'files') {
        courses = await Course.find(courseFilters)
          .select('_id title price rating enrollCount category createdAt thumbnailUrl userId')
          .sort({ enrollCount: -1, rating: -1 }).lean().limit(100);
      }
    }

    console.log(`✅ Files: ${files.length} | Courses: ${courses.length}`);

    // ── Format and deduplicate ────────────────────────────────────────────
    let results = deduplicateById([
      ...files.map(formatFile),
      ...courses.map(formatCourse),
    ]);

    // ── Score and sort ────────────────────────────────────────────────────
    if (sortBy === 'relevance' && correctedQuery.trim()) {
      results = results.map(item => ({
        ...item,
        _score: calculateCombinedWeightedScore(
          {
            filename:        item.title,
            title:           item.title,
            filedescription: item.description || '',
            description:     item.description || '',
            category:        item.category,
            price:           item.price,
            rating:          item.rating,
            downloadCount:   item.type === 'file'   ? item.interest : 0,
            enrollCount:     item.type === 'course' ? item.interest : 0,
            createdAt:       item.createdAt,
            creator:         item.creator,
          },
          correctedQuery
        ),
      })).sort((a, b) => b._score - a._score);
      console.log(`✅ Top relevance score: ${results[0]?._score?.toFixed(0)}`);
    } else {
      const SORT_FNS = {
        'price-asc':  (a, b) => (a.price || 0) - (b.price || 0),
        'price-desc': (a, b) => (b.price || 0) - (a.price || 0),
        'rating':     (a, b) => (b.rating || 0) - (a.rating || 0),
        'newest':     (a, b) => new Date(b.createdAt) - new Date(a.createdAt),
        'trending':   (a, b) => (b.interest || 0) - (a.interest || 0),
      };
      if (SORT_FNS[sortBy]) results.sort(SORT_FNS[sortBy]);
    }

    const total            = results.length;
    const paginatedResults = results.slice(skip, skip + limitNum);

    // ── Spelling suggestions ──────────────────────────────────────────────
    const spellingSuggestions = correctionResult.hasTypos
      ? correctionResult.corrections
          .filter(c => c.found && c.confidence < 1)
          .map(c => ({ original: c.original, corrected: c.corrected, confidence: c.confidence }))
      : [];

    // ── Did you mean? (async, non-blocking for speed) ─────────────────────
    const didYouMean = hadZeroResults ? await generateDidYouMean(q) : null;

    res.json({
      success: true,
      query: q,
      correctedQuery: correctionResult.hasTypos ? correctedQuery : null,
      searchMethodology: {
        approach: 'MULTI_TIER_COMBINED_WEIGHTED_SCORING',
        fieldWeights: {
          title:       { weight: 100, description: 'Exact/phrase match in title' },
          description: { weight: 60,  description: 'Relevant content in description' },
          category:    { weight: 40,  description: 'Category/subject match' },
          author:      { weight: 30,  description: 'Instructor / creator name' },
          price:       { weight: 20,  description: 'Price relevance (free/paid queries)' },
        },
        sortMethod: sortBy === 'relevance' ? 'WEIGHTED_RELEVANCE_SCORE' : sortBy.toUpperCase(),
        qualityBoost: 'Rating×5 + Popularity/100 + Recency bonus',
        tiers: ['Exact+Semantic', 'Individual keywords', 'Semantic category', 'Trending fallback'],
      },
      nlp: {
        entities: nlpResult.entities,
        summary:  nlpResult.summary,
        intents:  semanticFilters.intents,
      },
      semantic: {
        confidence:      semanticExpansion.confidence,
        expandedKeywords: semanticExpansion.allKeywords,
        relatedConcepts: semanticExpansion.relatedKeywords.slice(0, 5),
        learningPath:    safeLearningPath(semanticExpansion.primaryKeywords[0]),
      },
      spellCorrection: {
        hasTypos:      correctionResult.hasTypos,
        suggestions:   spellingSuggestions,
        expandedTerms: expandedTerms.slice(0, 5),
      },
      filters: {
        category:   categoryArray,
        priceMin:   priceMinF,
        priceMax:   effectivePriceMax,
        minRating:  minRatingF,
        sortBy,
        assetType,
        dateRange,
      },
      pagination: {
        page:  pageNum,
        limit: limitNum,
        total,
        pages: Math.ceil(total / limitNum),
      },
      results: paginatedResults,
      intelligence: {
        hadZeroResults,
        didYouMean,
        semanticExpansion: semanticExpansion.confidence > 0.7,
      },
    });
  } catch (err) {
    console.error('❌ /advanced error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ============================================================================
// ROUTE: GET /api/search/suggestions
// (Fixed: closed the comment block that was left open in the original)
// ============================================================================
router.get('/suggestions', async (req, res) => {
  try {
    const { q = '' } = req.query;
    if (q.length < 1) return res.json({ suggestions: [] });

    const searchRegex = new RegExp(q, 'i');

    const [files, courses, categories] = await Promise.all([
      File.find({ filename: searchRegex }).select('filename imageType').limit(8).lean(),
      Course.find({ title: searchRegex }).select('title').limit(8).lean(),
      File.distinct('category', { category: searchRegex }).then(cats => cats.slice(0, 8)),
    ]);

    let suggestions = [
      ...files.map(f => ({ text: f.filename, category: 'File',     score: fuzzyMatch(q, f.filename, 0.3) })),
      ...courses.map(c => ({ text: c.title,   category: 'Course',  score: fuzzyMatch(q, c.title,   0.3) })),
      ...categories.filter(Boolean).map(cat => ({ text: cat, category: 'Category', score: fuzzyMatch(q, cat, 0.3) })),
    ];

    suggestions.sort((a, b) => {
      if (a.text.toLowerCase() === q.toLowerCase()) return -1;
      if (b.text.toLowerCase() === q.toLowerCase()) return  1;
      return b.score - a.score;
    });

    res.json({
      success: true,
      suggestions: suggestions.map(({ score, ...rest }) => rest).slice(0, 12),
    });
  } catch (err) {
    console.error('❌ /suggestions error:', err);
    res.status(500).json({ success: true, suggestions: [] });
  }
});

// ============================================================================
// ROUTE: POST /api/search/parse-nlp
// ============================================================================
router.post('/parse-nlp', (req, res) => {
  try {
    const { query } = req.body;
    if (!query) return res.status(400).json({ error: 'Query is required' });

    const result = safeNlpParse(query);
    res.json({
      success: true,
      originalQuery: query,
      parsed: {
        entities: result.entities,
        filters:  result.filters,
        summary:  result.summary,
        readable: `Searching for: ${result.summary}`,
      },
    });
  } catch (err) {
    console.error('❌ /parse-nlp error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ============================================================================
// ROUTE: POST /api/search/spell-correct
// ============================================================================
router.post('/spell-correct', (req, res) => {
  try {
    const { query } = req.body;
    if (!query) return res.status(400).json({ error: 'Query is required' });

    const result = safeSpellCorrect(query);
    res.json({
      success: true,
      originalQuery: query,
      corrections: {
        correctedQuery:   result.correctedQuery,
        hasTypos:         result.hasTypos,
        confidence:       result.averageConfidence,
        suggestions:      result.corrections.map(c => ({
          term:      c.original,
          corrected: c.corrected,
          confidence: c.confidence,
          expanded:  c.expanded,
        })),
        allExpandedTerms: result.expandedTerms,
      },
    });
  } catch (err) {
    console.error('❌ /spell-correct error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ============================================================================
// ROUTE: POST /api/search/semantic-expand
// ============================================================================
router.post('/semantic-expand', (req, res) => {
  try {
    const { query } = req.body;
    if (!query) return res.status(400).json({ error: 'Query is required' });

    const expansion = safeSemanticExpand(query);
    const intent    = safeSemanticFilter(query);
    const path      = safeLearningPath(expansion.primaryKeywords[0]);

    res.json({
      success: true,
      originalQuery: query,
      semantic: {
        expansion: {
          primaryKeywords: expansion.primaryKeywords,
          relatedConcepts: expansion.relatedKeywords,
          allTerms:        expansion.allKeywords,
          confidence:      expansion.confidence,
        },
        intent:           intent.intents,
        suggestedFilters: intent.suggestedFilters,
        learningPath:     path,
        summary: `Looking for ${expansion.primaryKeywords.join(', ')}${
          path.length > 0 ? ' — Recommended path: ' + path.join(' → ') : ''
        }`,
      },
    });
  } catch (err) {
    console.error('❌ /semantic-expand error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ============================================================================
// ROUTE: POST /api/search/intelligent-parse
// ============================================================================
router.post('/intelligent-parse', (req, res) => {
  try {
    const { query } = req.body;
    if (!query) return res.status(400).json({ error: 'Query is required' });

    const corrected = safeSpellCorrect(query);
    const parsed    = safeNlpParse(corrected.correctedQuery);
    const semantic  = safeSemanticExpand(corrected.correctedQuery);

    res.json({
      success: true,
      originalQuery: query,
      intelligent: {
        spellCorrection: {
          correctedQuery: corrected.correctedQuery,
          hasTypos:       corrected.hasTypos,
          confidence:     corrected.averageConfidence,
        },
        nlp: {
          entities: parsed.entities,
          summary:  parsed.summary,
          filters:  parsed.filters,
        },
        semantic: {
          primaryConcepts: semantic.primaryKeywords,
          relatedConcepts: semantic.relatedKeywords,
          confidence:      semantic.confidence,
          learningPath:    safeLearningPath(semantic.primaryKeywords[0]),
        },
        recommended: {
          queryToUse:      corrected.correctedQuery,
          appliedFilters:  parsed.filters,
          searchConcepts:  semantic.allKeywords,
          expectedResults: `Find ${semantic.primaryKeywords.join(' & ')} materials${
            parsed.entities.hasCertificate  ? ' with certificates'    : ''
          }${parsed.entities.isProjectBased ? ' with hands-on projects' : ''}`,
        },
      },
    });
  } catch (err) {
    console.error('❌ /intelligent-parse error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ============================================================================
// ROUTE: GET /api/search/filters-options
// ============================================================================
router.get('/filters-options', async (req, res) => {
  try {
    const [categories, filePrices, coursePrices] = await Promise.all([
      File.distinct('category'),
      File.find({}).select('price rating').lean(),
      Course.find({}).select('price rating').lean(),
    ]);

    const all = [...filePrices, ...coursePrices];
    const prices  = all.map(i => i.price).filter(p => p != null);
    const ratings = all.map(i => i.rating).filter(r => r != null);

    res.json({
      categories: categories.filter(Boolean).sort(),
      priceRange: {
        min:     Math.floor(Math.min(...prices, 0)),
        max:     Math.ceil(Math.max(...prices, 1000)),
        average: prices.length ? Math.floor(prices.reduce((a, b) => a + b, 0) / prices.length) : 0,
      },
      ratings:     [0, 1, 2, 3, 4, 4.5, 5],
      sortOptions: [
        { value: 'relevance',  label: 'Most Relevant'      },
        { value: 'newest',     label: 'Newest First'       },
        { value: 'trending',   label: 'Trending'           },
        { value: 'price-asc',  label: 'Price: Low to High' },
        { value: 'price-desc', label: 'Price: High to Low' },
        { value: 'rating',     label: 'Highest Rated'      },
      ],
      dateRanges: [
        { value: 'all',      label: 'All Time'       },
        { value: 'week',     label: 'Past Week'      },
        { value: 'month',    label: 'Past Month'     },
        { value: '3months',  label: 'Past 3 Months'  },
        { value: '6months',  label: 'Past 6 Months'  },
        { value: 'year',     label: 'Past Year'      },
      ],
      advancedFilters: {
        difficulty: [
          { value: 'beginner',     label: '🟢 Beginner'     },
          { value: 'intermediate', label: '🟡 Intermediate'  },
          { value: 'advanced',     label: '🔴 Advanced'     },
          { value: 'expert',       label: '⚫ Expert'        },
        ],
        format: [
          { value: 'video',       label: '▶️ Video'          },
          { value: 'pdf',         label: '📄 PDF'            },
          { value: 'interactive', label: '🎮 Interactive'    },
          { value: 'live',        label: '🔴 Live Sessions'  },
          { value: 'document',    label: '📝 Document'       },
          { value: 'code',        label: '💻 Code'           },
        ],
        language: [
          { value: 'english',     label: '🇬🇧 English'       },
          { value: 'hindi',       label: '🇮🇳 Hindi'         },
          { value: 'spanish',     label: '🇪🇸 Spanish'       },
          { value: 'french',      label: '🇫🇷 French'        },
          { value: 'multilingual',label: '🌐 Multilingual'   },
        ],
        duration: [
          { value: 'short',  label: '⏱️ Under 2 hours' },
          { value: 'medium', label: '📽️ 2–10 hours'    },
          { value: 'long',   label: '📚 10+ hours'     },
        ],
        priceType: [
          { value: 'free',     label: '💰 Free'     },
          { value: 'paid',     label: '💳 Paid'     },
          { value: 'freemium', label: '🔄 Freemium' },
        ],
      },
    });
  } catch (err) {
    console.error('❌ /filters-options error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ============================================================================
// ROUTE: GET /api/search/dynamic-filters
// ============================================================================
router.get('/dynamic-filters', async (req, res) => {
  try {
    const { q = '', category = [], assetType = 'all' } = req.query;
    if (!q.trim()) return res.json({ dynamicFilters: {}, message: 'Enter search query first' });

    const categoryArray = Array.isArray(category) ? category : [category].filter(Boolean);
    const baseFilter = categoryArray.length > 0 ? { category: { $in: categoryArray } } : {};
    const qOr = [
      { filename:      { $regex: q, $options: 'i' } },
      { filedescription: { $regex: q, $options: 'i' } },
      { category:      { $regex: q, $options: 'i' } },
    ];

    let results = [];

    if (assetType !== 'courses') {
      const files = await File.find({ ...baseFilter, $or: qOr })
        .select('_id filename price rating downloadCount category').lean().limit(100);
      results = [...results, ...files.map(f => ({ ...f, type: 'file', title: f.filename, interest: f.downloadCount }))];
    }

    if (assetType !== 'files') {
      const courses = await Course.find({
        ...baseFilter,
        $or: [{ title: { $regex: q, $options: 'i' } }, { description: { $regex: q, $options: 'i' } }],
      }).select('_id title price rating enrollCount category').lean().limit(100);
      results = [...results, ...courses.map(c => ({ ...c, type: 'course', interest: c.enrollCount }))];
    }

    res.json({ success: true, dynamicFilters: buildDynamicFilters(results), resultCount: results.length });
  } catch (err) {
    console.error('❌ /dynamic-filters error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ============================================================================
// ROUTE: GET /api/search/faceted-search
// ============================================================================
router.get('/faceted-search', async (req, res) => {
  try {
    const { q = '', category = '' } = req.query;

    const pipeline = [];
    if (q.trim()) {
      pipeline.push({
        $match: {
          $or: [
            { filename:      { $regex: q, $options: 'i' } },
            { filedescription: { $regex: q, $options: 'i' } },
            { category:      { $regex: q, $options: 'i' } },
          ],
        },
      });
    }
    if (category) pipeline.push({ $match: { category } });

    pipeline.push({
      $facet: {
        categories: [{ $group: { _id: '$category', count: { $sum: 1 } } }, { $sort: { count: -1 } }, { $limit: 15 }],
        results:    [{ $limit: 20 }],
        priceStats: [{ $group: { _id: null, min: { $min: '$price' }, max: { $max: '$price' }, avg: { $avg: '$price' } } }],
        ratingStats:[{ $group: { _id: null, min: { $min: '$rating' }, max: { $max: '$rating' }, avg: { $avg: '$rating' } } }],
      },
    });

    const [fileAgg, courseAgg] = await Promise.all([
      File.aggregate(pipeline),
      Course.aggregate(pipeline),
    ]);

    res.json({
      success: true,
      facets: (fileAgg[0]?.categories || []).map(c => ({ name: c._id, count: c.count })),
      results: [
        ...(fileAgg[0]?.results || []).map(f => ({ _id: f._id, title: f.filename, price: f.price, rating: f.rating, category: f.category, type: 'file' })),
        ...(courseAgg[0]?.results || []).map(c => ({ _id: c._id, title: c.title, price: c.price, rating: c.rating, category: c.category, type: 'course' })),
      ],
      stats: {
        price:  fileAgg[0]?.priceStats?.[0]  || { min: 0, max: 1000, avg: 500 },
        rating: fileAgg[0]?.ratingStats?.[0] || { min: 0, max: 5,    avg: 3.5 },
      },
      selectedFilters: { category },
    });
  } catch (err) {
    console.error('❌ /faceted-search error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ============================================================================
// ROUTE: GET /api/search/filter-stats
// ============================================================================
router.get('/filter-stats', async (req, res) => {
  try {
    const { q = '' } = req.query;

    const fileMatch = q.trim()
      ? { $or: [{ filename: { $regex: q, $options: 'i' } }, { filedescription: { $regex: q, $options: 'i' } }] }
      : {};
    const courseMatch = q.trim()
      ? { $or: [{ title: { $regex: q, $options: 'i' } }, { description: { $regex: q, $options: 'i' } }] }
      : {};

    const [files, courses] = await Promise.all([
      File.aggregate([{ $match: fileMatch }, { $group: { _id: null, minPrice: { $min: '$price' }, maxPrice: { $max: '$price' }, avgPrice: { $avg: '$price' }, minRating: { $min: '$rating' }, maxRating: { $max: '$rating' }, avgRating: { $avg: '$rating' }, count: { $sum: 1 } } }]),
      Course.aggregate([{ $match: courseMatch }, { $group: { _id: null, minPrice: { $min: '$price' }, maxPrice: { $max: '$price' }, avgPrice: { $avg: '$price' }, minRating: { $min: '$rating' }, maxRating: { $max: '$rating' }, avgRating: { $avg: '$rating' }, count: { $sum: 1 } } }]),
    ]);

    const fs = files[0]  || { minPrice: 0, maxPrice: 1000, avgPrice: 500, minRating: 0, maxRating: 5, avgRating: 3.5, count: 0 };
    const cs = courses[0] || { minPrice: 0, maxPrice: 1000, avgPrice: 500, minRating: 0, maxRating: 5, avgRating: 3.5, count: 0 };

    res.json({
      success: true,
      price: {
        min: Math.min(fs.minPrice, cs.minPrice),
        max: Math.max(fs.maxPrice, cs.maxPrice),
        avg: ((fs.avgPrice || 0) + (cs.avgPrice || 0)) / 2,
        presets: {
          budget:   { min: 0,    max: 500,  label: 'Budget (₹0–500)'       },
          midrange: { min: 500,  max: 1500, label: 'Mid-range (₹500–1500)' },
          premium:  { min: 1500, max: 5000, label: 'Premium (₹1500+)'      },
          free:     { min: 0,    max: 0,    label: 'Free Only'              },
        },
      },
      rating: {
        min: Math.min(fs.minRating, cs.minRating),
        max: Math.max(fs.maxRating, cs.maxRating),
        avg: ((fs.avgRating || 0) + (cs.avgRating || 0)) / 2,
      },
      duration: {
        presets: {
          short:  { min: 0,  max: 2,   label: 'Short (1–2h)'    },
          medium: { min: 2,  max: 10,  label: 'Medium (2–10h)'  },
          full:   { min: 10, max: 100, label: 'Full course (10+h)' },
        },
      },
      resultCount: fs.count + cs.count,
    });
  } catch (err) {
    console.error('❌ /filter-stats error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ============================================================================
// ROUTE: POST /api/search/saved  — Save a search
// ============================================================================
router.post('/saved', authenticateJWT_user, async (req, res) => {
  try {
    const userId = req.user?._id;
    if (!userId) return res.status(401).json({ error: 'Unauthorized' });

    const { searchName, query, filters, resultCount } = req.body;
    if (!searchName || !query) return res.status(400).json({ error: 'searchName and query required' });

    const saved = await new SavedSearch({ userId, searchName, query, filters, resultCount }).save();
    res.json({ success: true, message: 'Search saved', search: saved });
  } catch (err) {
    console.error('❌ POST /saved error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ============================================================================
// ROUTE: GET /api/search/saved  — Get user's saved searches
// ============================================================================
router.get('/saved', authenticateJWT_user, async (req, res) => {
  try {
    const userId = req.user?._id;
    if (!userId) return res.status(401).json({ error: 'Unauthorized' });

    const searches = await SavedSearch.find({ userId }).sort({ createdAt: -1 }).lean();
    res.json({ success: true, searches });
  } catch (err) {
    console.error('❌ GET /saved error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ============================================================================
// ROUTE: DELETE /api/search/saved/:searchId
// ============================================================================
router.delete('/saved/:searchId', authenticateJWT_user, async (req, res) => {
  try {
    const userId = req.user?._id;
    if (!userId) return res.status(401).json({ error: 'Unauthorized' });

    const result = await SavedSearch.findOneAndDelete({ _id: req.params.searchId, userId });
    if (!result) return res.status(404).json({ error: 'Search not found' });

    res.json({ success: true, message: 'Search deleted' });
  } catch (err) {
    console.error('❌ DELETE /saved error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ============================================================================
// ROUTE: PUT /api/search/saved/:searchId
// ============================================================================
router.put('/saved/:searchId', authenticateJWT_user, async (req, res) => {
  try {
    const userId = req.user?._id;
    if (!userId) return res.status(401).json({ error: 'Unauthorized' });

    const { searchName, filters } = req.body;
    const updated = await SavedSearch.findOneAndUpdate(
      { _id: req.params.searchId, userId },
      { searchName, filters, updatedAt: new Date() },
      { new: true }
    );
    if (!updated) return res.status(404).json({ error: 'Search not found' });

    res.json({ success: true, search: updated });
  } catch (err) {
    console.error('❌ PUT /saved error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ============================================================================
// ROUTE: GET /api/search/trending
// ============================================================================
router.get('/trending', async (req, res) => {
  try {
    const [trendingFiles, trendingCourses] = await Promise.all([
      File.find().select('_id filename price rating downloadCount category createdAt imageType previewUrl user').sort({ downloadCount: -1 }).limit(6).lean(),
      Course.find().select('_id title price rating enrollCount category createdAt thumbnailUrl userId').sort({ enrollCount: -1 }).limit(6).lean(),
    ]);

    const results = deduplicateById([
      ...trendingFiles.map(formatFile),
      ...trendingCourses.map(formatCourse),
    ]).sort((a, b) => (b.interest || 0) - (a.interest || 0)).slice(0, 12);

    res.json({ success: true, trending: results });
  } catch (err) {
    console.error('❌ /trending error:', err);
    res.status(500).json({ success: false, trending: [] });
  }
});

// ============================================================================
// ROUTE: GET /api/search/popular
// ============================================================================
router.get('/popular', async (req, res) => {
  try {
    const [popularFiles, popularCourses] = await Promise.all([
      File.find({ rating: { $gte: 3.5 } }).select('_id filename price rating downloadCount category createdAt imageType previewUrl user').sort({ rating: -1, downloadCount: -1 }).limit(6).lean(),
      Course.find({ rating: { $gte: 3.5 } }).select('_id title price rating enrollCount category createdAt thumbnailUrl userId').sort({ rating: -1, enrollCount: -1 }).limit(6).lean(),
    ]);

    const results = deduplicateById([
      ...popularFiles.map(formatFile),
      ...popularCourses.map(formatCourse),
    ]).sort((a, b) => (b.rating || 0) - (a.rating || 0)).slice(0, 12);

    res.json({ success: true, popular: results });
  } catch (err) {
    console.error('❌ /popular error:', err);
    res.status(500).json({ success: false, popular: [] });
  }
});

// ============================================================================
// ROUTE: GET /api/search/smart-correct
// ============================================================================
router.get('/smart-correct', async (req, res) => {
  try {
    const { q = '' } = req.query;
    if (q.length < 2) return res.json({ success: true, suggestions: [], corrections: [], intent: null });

    const context = analyzeSearchContext(q);
    const [corrections, suggestionsList] = await Promise.all([
      generateDidYouMean(q),
      File.find({ filename: new RegExp(q, 'i') }).select('filename').limit(5).lean().then(r => r.map(f => f.filename)),
    ]);

    res.json({
      success: true,
      query: q,
      context: { detectedIntents: context.intents, keywords: context.keywords, isSpecific: context.isSpecific },
      suggestions: suggestionsList,
      corrections:  corrections || [],
      instantResults: suggestionsList.length > 0,
      confidence: {
        exactMatch:      suggestionsList.length > 0,
        fuzzyMatch:      !!(corrections && corrections.length > 0),
        intentDetection: context.intents.length > 0,
      },
    });
  } catch (err) {
    console.error('❌ /smart-correct error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ============================================================================
// ROUTE: GET /api/search/personalized
// ============================================================================
router.get('/personalized', authenticateJWT_user, async (req, res) => {
  try {
    const userId = req.user?._id;
    const recentSearches = await SavedSearch.find({ userId }).sort({ createdAt: -1 }).limit(5).lean();
    const searchedCategories = [...new Set(recentSearches.flatMap(s => s.filters?.category || []))].slice(0, 5);

    let recommendations = [];
    if (searchedCategories.length > 0) {
      const [files, courses] = await Promise.all([
        File.find({ category: { $in: searchedCategories } }).select('_id filename price rating downloadCount category createdAt imageType previewUrl user').sort({ downloadCount: -1, rating: -1 }).limit(8).lean(),
        Course.find({ category: { $in: searchedCategories } }).select('_id title price rating enrollCount category createdAt thumbnailUrl userId').sort({ enrollCount: -1, rating: -1 }).limit(8).lean(),
      ]);

      recommendations = deduplicateById([
        ...files.map(f => ({ ...formatFile(f), reason: `Related to ${f.category}` })),
        ...courses.map(c => ({ ...formatCourse(c), reason: `Related to ${c.category}` })),
      ]).slice(0, 12);
    }

    res.json({
      success: true,
      recommendations,
      basedOn:       searchedCategories,
      searchHistory: recentSearches.map(s => s.query),
    });
  } catch (err) {
    console.error('❌ /personalized error:', err);
    res.status(500).json({ success: false, recommendations: [] });
  }
});

// ============================================================================
// ROUTE: GET /api/search/related/:itemId
// BUG FIX: was reading itemId from req.query instead of req.params
// ============================================================================
router.get('/related/:itemId', async (req, res) => {
  try {
    const { itemId } = req.params;            // ← Fixed: was req.query.itemId
    const { type = 'file' } = req.query;

    const Model   = type === 'course' ? Course : File;
    const item    = await Model.findById(itemId).lean();
    if (!item) return res.status(404).json({ error: 'Item not found' });

    const titleField = type === 'course' ? 'title' : 'filename';
    const keywords   = (item[titleField] || '').split(/\s+/).filter(w => w.length > 3);
    const keywordOr  = keywords.slice(0, 5).map(kw => ({ [titleField]: { $regex: kw, $options: 'i' } }));

    const similar = await Model.find({
      _id: { $ne: itemId },
      $or: [{ category: item.category }, ...keywordOr],
    })
      .select(type === 'course'
        ? '_id title price rating enrollCount category createdAt thumbnailUrl userId'
        : '_id filename price rating downloadCount category createdAt imageType previewUrl user')
      .sort({ rating: -1, ...(type === 'course' ? { enrollCount: -1 } : { downloadCount: -1 }) })
      .limit(12)
      .lean();

    const formatted = similar.map(i => type === 'course' ? formatCourse(i) : formatFile(i));
    res.json({ success: true, related: formatted });
  } catch (err) {
    console.error('❌ /related error:', err);
    res.status(500).json({ success: false, related: [] });
  }
});

// ============================================================================
// ROUTE: GET /api/search/trending-advanced
// ============================================================================
router.get('/trending-advanced', async (req, res) => {
  try {
    const { timeRange = 'week', category = '', limit = 8 } = req.query;
    const DAYS = { today: 1, week: 7, month: 30, quarter: 90, year: 365 };
    const days = DAYS[timeRange] || 7;
    const dateFilter   = { createdAt: { $gte: new Date(Date.now() - days * 86400000) } };
    const catFilter    = category ? { category } : {};
    const limitNum     = parseInt(limit) || 8;

    const [byDownloads, byEnrollment, byRating] = await Promise.all([
      File.find({ ...dateFilter, ...catFilter }).select('_id filename price rating downloadCount category createdAt imageType previewUrl user').sort({ downloadCount: -1 }).limit(limitNum).lean(),
      Course.find({ ...dateFilter, ...catFilter }).select('_id title price rating enrollCount category createdAt thumbnailUrl userId').sort({ enrollCount: -1 }).limit(limitNum).lean(),
      File.find({ ...dateFilter, ...catFilter, rating: { $gte: 3 } }).select('_id filename price rating downloadCount category createdAt imageType previewUrl user').sort({ rating: -1, downloadCount: -1 }).limit(limitNum).lean(),
    ]);

    res.json({
      success: true,
      trending: {
        byDownloads:  byDownloads.map(f => ({ ...formatFile(f),   badge: 'Most Downloaded' })),
        byEnrollment: byEnrollment.map(c => ({ ...formatCourse(c), badge: 'Most Enrolled'   })),
        byRating:     byRating.map(f => ({ ...formatFile(f),      badge: 'Highest Rated'   })),
      },
      timeRange,
      category: category || 'all',
    });
  } catch (err) {
    console.error('❌ /trending-advanced error:', err);
    res.status(500).json({ success: false, trending: {} });
  }
});

// ============================================================================
// ROUTE: POST /api/search/track-search
// ============================================================================
router.post('/track-search', async (req, res) => {
  try {
    const { query, category, resultCount, userId } = req.body;
    if (!query) return res.status(400).json({ error: 'Query required' });

    await new SavedSearch({
      userId: userId || null,
      query,
      searchName: query,
      filters:    { category: category ? [category] : [] },
      resultCount: resultCount || 0,
    }).save();

    res.json({ success: true, message: 'Search tracked' });
  } catch (err) {
    console.error('❌ /track-search error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ============================================================================
// ROUTE: GET /api/search/popular-searches
// ============================================================================
router.get('/popular-searches', async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 10;
    const popular = await SavedSearch.aggregate([
      { $group: { _id: '$query', count: { $sum: 1 }, lastSearched: { $max: '$createdAt' } } },
      { $sort: { count: -1 } },
      { $limit: limit },
    ]);

    res.json({
      success: true,
      popularSearches: popular.map(s => ({ query: s._id, searches: s.count, lastSearched: s.lastSearched })),
    });
  } catch (err) {
    console.error('❌ /popular-searches error:', err);
    res.status(500).json({ success: false, popularSearches: [] });
  }
});

// ============================================================================
// ROUTE: GET /api/search/auto-complete
// ============================================================================
router.get('/auto-complete', async (req, res) => {
  try {
    const { q = '', category = '', limit = 15 } = req.query;
    if (q.length < 1) return res.json({ suggestions: [] });

    const searchRegex  = new RegExp(q, 'i');
    const catFilter    = category ? { category } : {};

    const [files, courses, categories, searches] = await Promise.all([
      File.find({ filename: searchRegex, ...catFilter }).select('filename').limit(5).lean(),
      Course.find({ title: searchRegex, ...catFilter }).select('title').limit(5).lean(),
      File.distinct('category', { category: searchRegex }).then(c => c.slice(0, 3)),
      SavedSearch.distinct('query', { query: searchRegex }).then(r => r.slice(0, 5)),
    ]);

    let suggestions = [
      ...files.map(f   => ({ text: f.filename, type: 'file',     score: fuzzyMatch(q, f.filename, 0.3) })),
      ...courses.map(c => ({ text: c.title,    type: 'course',   score: fuzzyMatch(q, c.title,   0.3) })),
      ...categories.filter(Boolean).map(cat => ({ text: cat, type: 'category', score: fuzzyMatch(q, cat, 0.3) })),
      ...searches.map(s => ({ text: s, type: 'recent', score: fuzzyMatch(q, s, 0.3) })),
    ];

    // Deduplicate by lowercase text
    const seen = new Set();
    suggestions = suggestions
      .sort((a, b) => {
        if (a.text.toLowerCase() === q.toLowerCase()) return -1;
        if (b.text.toLowerCase() === q.toLowerCase()) return  1;
        return b.score - a.score;
      })
      .filter(item => {
        const key = item.text.toLowerCase();
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
      })
      .map(({ score, ...rest }) => rest)
      .slice(0, parseInt(limit));

    res.json({ success: true, suggestions });
  } catch (err) {
    console.error('❌ /auto-complete error:', err);
    res.status(500).json({ success: false, suggestions: [] });
  }
});

// ============================================================================
// ROUTE: GET /api/search/explore
// ============================================================================
router.get('/explore', async (req, res) => {
  try {
    const { category, sortBy = 'trending', limit = 12 } = req.query;
    const SORT_MAP = { new: { createdAt: -1 }, rated: { rating: -1 }, price: { price: 1 }, trending: { downloadCount: -1 } };
    const sortOption = SORT_MAP[sortBy] || { downloadCount: -1 };

    const categories = category ? [category] : await File.distinct('category');

    const explore = await Promise.all(
      categories.slice(0, 6).map(async cat => {
        const files = await File.find({ category: cat })
          .select('_id filename price rating downloadCount category createdAt imageType previewUrl user')
          .sort(sortOption).limit(parseInt(limit)).lean();

        return {
          category: cat,
          items: files.map(f => ({
            _id:      f._id,
            title:    f.filename,
            price:    f.price,
            rating:   f.rating,
            interest: f.downloadCount,
            type:     'file',
            image:    buildPreviewUrl(f),
          })),
        };
      })
    );

    res.json({
      success: true,
      explore:         explore.filter(e => e.items.length > 0),
      totalCategories: categories.length,
    });
  } catch (err) {
    console.error('❌ /explore error:', err);
    res.status(500).json({ success: false, explore: [] });
  }
});

module.exports = router;
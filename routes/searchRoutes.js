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
// HELPER: Fuzzy matching for typo tolerance
// ============================================================================
function levenshteinDistance(str1, str2) {
    const track = Array(str2.length + 1).fill(null).map(() =>
        Array(str1.length + 1).fill(null));
    for (let i = 0; i <= str1.length; i += 1) track[0][i] = i;
    for (let j = 0; j <= str2.length; j += 1) track[j][0] = j;
    for (let j = 1; j <= str2.length; j += 1) {
        for (let i = 1; i <= str1.length; i += 1) {
            const indicator = str1[i - 1] === str2[j - 1] ? 0 : 1;
            track[j][i] = Math.min(
                track[j][i - 1] + 1,
                track[j - 1][i] + 1,
                track[j - 1][i - 1] + indicator
            );
        }
    }
    return track[str2.length][str1.length];
}

function fuzzyMatch(query, text, threshold = 0.7) {
    const distance = levenshteinDistance(query.toLowerCase(), text.toLowerCase());
    const maxLen = Math.max(query.length, text.length);
    const similarity = 1 - (distance / maxLen);
    return similarity >= threshold ? similarity : 0;
}

// ============================================================================
// HELPER: Calculate relevance score for results
// ============================================================================
function calculateRelevanceScore(item, query, filters) {
    let score = 0;
    const titleLower = item.title.toLowerCase();
    const queryLower = query.toLowerCase();
    const queryWords = queryLower.split(/\s+/);

    // 1. Exact match in title (highest priority)
    if (titleLower === queryLower) score += 100;
    // 2. Title starts with query
    else if (titleLower.startsWith(queryLower)) score += 80;
    // 3. Whole query words match in order
    else if (titleLower.includes(queryLower)) score += 60;
    // 4. Individual word matches
    else {
        const wordMatches = queryWords.filter(word => titleLower.includes(word)).length;
        score += (wordMatches / queryWords.length) * 50;
    }

    // Fuzzy match bonus
    const fuzzyScore = fuzzyMatch(queryLower, titleLower, 0.6);
    if (fuzzyScore > 0) score += fuzzyScore * 30;

    // Rating boost
    score += (item.rating || 0) * 5;

    // Popularity boost
    score += Math.min((item.interest || 0) / 100, 20);

    // Recency boost (items from last 30 days get extra score)
    const daysOld = (Date.now() - new Date(item.createdAt).getTime()) / (1000 * 60 * 60 * 24);
    if (daysOld <= 30) score += 10;
    else if (daysOld <= 90) score += 5;

    // Category match bonus
    if (filters.categoryArray && filters.categoryArray.length > 0) {
        if (filters.categoryArray.includes(item.category)) score += 15;
    }

    // Price preference bonus
    if (filters.priceMin || filters.priceMax) {
        const priceMatch = item.price >= filters.priceMin && item.price <= filters.priceMax;
        if (priceMatch) score += 10;
    }

    return score;
}

// ============================================================================
// HELPER: Extract search intent and context
// ============================================================================
function analyzeSearchContext(query) {
    const queryLower = query.toLowerCase();
    const keywords = queryLower.split(/\s+/);

    const intents = {
        learning: ['learn', 'tutorial', 'course', 'class', 'training', 'education'],
        reference: ['guide', 'manual', 'documentation', 'reference', 'pdf', 'ebook'],
        certification: ['certificate', 'certification', 'exam', 'test', 'preparation'],
        project: ['project', 'example', 'sample', 'template', 'starter'],
        debugging: ['fix', 'error', 'bug', 'debug', 'troubleshoot', 'solution'],
        specialization: ['advanced', 'pro', 'expert', 'master', 'professional']
    };

    let detectedIntents = [];
    for (const [intent, words] of Object.entries(intents)) {
        if (words.some(word => queryLower.includes(word))) {
            detectedIntents.push(intent);
        }
    }

    return {
        keywords,
        intents: detectedIntents.length > 0 ? detectedIntents : ['general'],
        isSpecific: keywords.length > 2,
        hasSpecialChars: /[^\w\s]/.test(query),
        length: keywords.length
    };
}

// ============================================================================
// HELPER: Generate "Did you mean?" suggestions using fuzzy matching
// ============================================================================
async function generateDidYouMean(query) {
    if (query.length < 3) return null;

    const files = await File.find().select('filename').lean().limit(100);
    const courses = await Course.find().select('title').lean().limit(100);

    const allTitles = [
        ...files.map(f => f.filename),
        ...courses.map(c => c.title)
    ];

    const suggestions = allTitles
        .map(title => ({
            title,
            similarity: fuzzyMatch(query.toLowerCase(), title.toLowerCase(), 0.5)
        }))
        .filter(item => item.similarity > 0)
        .sort((a, b) => b.similarity - a.similarity)
        .slice(0, 3)
        .map(item => item.title);

    return suggestions.length > 0 ? suggestions : null;
}

// ============================================================================
// HELPER: Get related categories and items
// ============================================================================
async function getRelatedSuggestions(query, category) {
    const context = analyzeSearchContext(query);

    // Get related categories
    const allCategories = await File.distinct('category', {
        $or: [
            { category: new RegExp(context.keywords[0] || '', 'i') },
            { category: { $regex: category, $options: 'i' } }
        ]
    });
    const relatedCategories = allCategories.slice(0, 5);

    // Get trending items in related categories
    const relatedItems = await Promise.all(
        (relatedCategories || [category]).map(cat =>
            File.find({ category: cat })
                .select('_id filename price rating downloadCount category createdAt imageType previewUrl user')
                .sort({ downloadCount: -1, rating: -1 })
                .limit(4)
                .lean()
        )
    );

    return {
        relatedCategories: relatedCategories.filter(c => c),
        relatedItems: relatedItems.flat().slice(0, 8)
    };
}

// ============================================================================
// HELPER: Build preview URL for files
// ============================================================================
function buildPreviewUrl(file, CLOUDFRONT_DOMAIN = process.env.CF_DOMAIN_PROFILES_COURSES ? process.env.CF_DOMAIN_PROFILES_COURSES.replace(/^https:\/\//g, "") : "d3epchi0htsp3c.cloudfront.net") {
  // First, use existing previewUrl if available
  if (file.previewUrl && file.previewUrl.trim()) {
    return file.previewUrl;
  }
  
  // Fallback: Build CloudFront URL from imageType if available
  if (file.imageType) {
    let ext = file.imageType.toLowerCase();
    if (ext === 'jpeg') ext = 'jpg';
    return `https://${CLOUDFRONT_DOMAIN}/files-previews/images/${file._id}.${ext}`;
  }
  
  // Final fallback: Return null for placeholder
  return null;
}

// ============================================================================
// ENHANCED SEARCH: Parse boolean queries (AND, OR, NOT, field-specific)
// ============================================================================
function parseBooleanQuery(query) {
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
  
  // Parse boolean operators
  const andOperator = query.match(/\bAND\b/i);
  const orOperator = query.match(/\bOR\b/i);
  const notOperator = query.match(/\bNOT\b/gi);
  
  return {
    fieldSearches,
    cleanQuery: cleanQuery.trim(),
    hasAnd: !!andOperator,
    hasOr: !!orOperator,
    hasNot: notOperator ? notOperator.length : 0,
    originalQuery: query
  };
}

// ============================================================================
// ENHANCED SEARCH: Calculate weighted combined field score
// ============================================================================
function calculateCombinedWeightedScore(item, query, type) {
  let totalScore = 0;
  const queryWords = query.toLowerCase().split(/\s+/).filter(w => w.length > 0);
  
  // If no query, use popularity score
  if (queryWords.length === 0) {
    return (item.rating || 0) * 10 + Math.min((item.downloadCount || item.enrollCount || 0) / 50, 30);
  }
  
  // ========== TITLE SCORING (Weight: 100) ==========
  const titleLower = (item.filename || item.title || '').toLowerCase();
  let titleScore = 0;
  if (titleLower === query.toLowerCase()) {
    titleScore = 100; // exact match
  } else if (titleLower.startsWith(query.toLowerCase())) {
    titleScore = 90; // starts with
  } else if (titleLower.includes(query.toLowerCase())) {
    titleScore = 75; // contains full query
  } else {
    // Individual word matches
    const titleMatches = queryWords.filter(w => titleLower.includes(w)).length;
    titleScore = (titleMatches / queryWords.length) * 60;
    
    // Fuzzy match for typos
    const fuzzyScore = fuzzyMatch(query.toLowerCase(), titleLower, 0.5);
    if (fuzzyScore > 0) titleScore = Math.max(titleScore, fuzzyScore * 50);
  }
  totalScore += titleScore * 100; // Weight multiplier for title
  
  // ========== DESCRIPTION SCORING (Weight: 60) ==========
  const description = (item.filedescription || item.description || '').toLowerCase();
  let descriptionScore = 0;
  if (description.length > 0) {
    if (description.includes(query.toLowerCase())) {
      descriptionScore = 70;
    } else {
      const descMatches = queryWords.filter(w => description.includes(w)).length;
      descriptionScore = (descMatches / queryWords.length) * 50;
    }
  }
  totalScore += descriptionScore * 60; // Weight multiplier for description
  
  // ========== CATEGORY SCORING (Weight: 40) ==========
  const category = (item.category || '').toLowerCase();
  let categoryScore = 0;
  if (category.includes(query.toLowerCase())) {
    categoryScore = 80;
  } else {
    const catMatches = queryWords.filter(w => category.includes(w)).length;
    categoryScore = (catMatches / queryWords.length) * 60;
  }
  totalScore += categoryScore * 40; // Weight multiplier for category
  
  // ========== AUTHOR/CREATOR SCORING (Weight: 30) ==========
  let authorScore = 0;
  if (item.creator || item.creatorName) {
    const author = (typeof item.creator === 'string' ? item.creator : item.creatorName || '').toLowerCase();
    if (author && author.includes(query.toLowerCase())) {
      authorScore = 60;
    }
  }
  totalScore += authorScore * 30; // Weight multiplier for author
  
  // ========== PRICE RELEVANCE (Weight: 20) ==========
  let priceScore = 0;
  if (queryWords.some(w => ['free', 'paid', 'premium', 'course', 'tutorial'].includes(w))) {
    if ((item.price || 0) === 0 && query.toLowerCase().includes('free')) {
      priceScore = 50;
    } else if ((item.price || 0) > 0 && query.toLowerCase().includes('paid')) {
      priceScore = 50;
    }
  }
  totalScore += priceScore * 20; // Weight multiplier for price
  
  // ========== QUALITY METRICS (Boosters) ==========
  // Rating boost (5 points per star)
  totalScore += ((item.rating || 0) * 5);
  
  // Popularity boost (downloads/enrollments)
  const popularity = (item.downloadCount || item.enrollCount || 0);
  totalScore += Math.min(popularity / 100, 40);
  
  // Recency boost
  const daysOld = (Date.now() - new Date(item.createdAt || Date.now()).getTime()) / (1000 * 60 * 60 * 24);
  if (daysOld <= 7) totalScore += 30;
  else if (daysOld <= 30) totalScore += 20;
  else if (daysOld <= 90) totalScore += 10;
  
  return Math.max(0, totalScore);
}

// ============================================================================
// ENHANCED SEARCH: Apply field-specific filters
// ============================================================================
function buildFieldSpecificQuery(fieldSearches, baseFilter) {
  let query = { ...baseFilter };
  
  if (fieldSearches.title) {
    query.filename = { $regex: fieldSearches.title[0], $options: 'i' };
  }
  if (fieldSearches.author) {
    // Would need author lookup here
  }
  if (fieldSearches.category) {
    query.category = { $regex: fieldSearches.category[0], $options: 'i' };
  }
  if (fieldSearches.price) {
    const priceVal = parseFloat(fieldSearches.price[0]);
    if (!isNaN(priceVal)) {
      query.price = { $lte: priceVal };
    }
  }
  if (fieldSearches.rating) {
    const ratingVal = parseFloat(fieldSearches.rating[0]);
    if (!isNaN(ratingVal)) {
      query.rating = { $gte: ratingVal };
    }
  }
  
  return query;
}


// ============================================================================
// HELPER: Create text index for full-text search
// ============================================================================
async function ensureTextIndices() {
  try {
    await File.collection.createIndex({ filename: 'text', filedescription: 'text', category: 'text' });
    await Course.collection.createIndex({ title: 'text', description: 'text', category: 'text' });
  } catch (err) {
    // Indices may already exist
    console.log('📚 Text indices already exist or error creating:', err.message);
  }
}

/**
 * GET /api/search/advanced
 * Advanced AI-powered search with semantic understanding, NLP parsing, and spell correction
 * Integrates: Semantic Search, NLP for entity extraction, Spell Correction & Expansion
 */
router.get('/advanced', async (req, res) => {
    try {
        await ensureTextIndices();

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
            limit = 12
        } = req.query;

        const skip = (parseInt(page) - 1) * parseInt(limit);
        const categoryArray = Array.isArray(category) ? category : [category].filter(c => c);

        // ========== SPELL CORRECTION & EXPANSION ==========
        console.log('🔤 Original query:', q);
        const correctionResult = spellCorrection.correctAndExpandQuery(q);
        console.log('✅ Corrected:', correctionResult.correctedQuery);
        console.log('📚 Expanded terms:', correctionResult.expandedTerms);
        
        const correctedQuery = correctionResult.correctedQuery || q;
        const expandedTerms = correctionResult.expandedTerms;

        // ========== NLP ENTITY EXTRACTION ==========
        const nlpResult = nlpService.parseNaturalLanguageQuery(correctedQuery);
        console.log('🧠 NLP Entities:', nlpResult.entities);
        console.log('📋 Query Summary:', nlpResult.summary);

        // Override filters if NLP detected specific requirements
        if (nlpResult.filters.durationMax) {
            // Duration filter could be applied if your schema supports it
        }
        if (nlpResult.filters.priceMax) {
            priceMax = Math.min(priceMax, nlpResult.filters.priceMax);
        }
        if (nlpResult.filters.level) {
            // Level filter could be applied
        }

        // ========== SEMANTIC SEARCH EXPANSION ==========
        const semanticExpansion = semanticSearch.expandSemanticQuery(correctedQuery);
        const semanticFilters = semanticSearch.buildSemanticFilter(correctedQuery);
        console.log('🌐 Semantic keywords:', semanticExpansion.allKeywords);
        console.log('🎯 Semantic filters:', semanticFilters.suggestedFilters);

        // ========== BUILD SEARCH FILTERS ==========
        let dateFilter = {};
        const now = new Date();
        if (dateRange !== 'all') {
            const daysAgo = {
                'week': 7,
                'month': 30,
                '3months': 90,
                '6months': 180,
                'year': 365
            }[dateRange] || null;

            if (daysAgo) {
                dateFilter = {
                    createdAt: {
                        $gte: new Date(now.getTime() - daysAgo * 24 * 60 * 60 * 1000)
                    }
                };
            }
        }

        let sortOption = {};
        switch (sortBy) {
            case 'price-asc':
                sortOption = { price: 1 };
                break;
            case 'price-desc':
                sortOption = { price: -1 };
                break;
            case 'rating':
                sortOption = { rating: -1 };
                break;
            case 'newest':
                sortOption = { createdAt: -1 };
                break;
            case 'trending':
                sortOption = { downloadCount: -1 };
                break;
            default:
                sortOption = { _id: -1 };
        }

        const fileFilters = {
            ...(priceMin > 0 || priceMax < 10000 ? { price: { $gte: parseFloat(priceMin), $lte: parseFloat(priceMax) } } : {}),
            ...(minRating > 0 ? { rating: { $gte: parseFloat(minRating) } } : {}),
            ...dateFilter,
            ...(categoryArray.length > 0 && { category: { $in: categoryArray } })
        };

        const courseFilters = { ...fileFilters };

        let creatorId = null;
        if (creator) {
            const creatorUser = await User.findOne({
                $or: [
                    { username: new RegExp(creator, 'i') },
                    { email: new RegExp(creator, 'i') }
                ]
            });
            if (creatorUser) {
                creatorId = creatorUser._id;
                fileFilters.user = creatorId;
                courseFilters.userId = creatorId;
            }
        }

        // ========== TIER 1: EXACT & SEMANTIC KEYWORD MATCHES ==========
        let files = [];
        let courses = [];
        let hadZeroResults = false;

        if (correctedQuery && correctedQuery.trim()) {
            if (assetType === 'all' || assetType === 'files') {
                const fileQuery = {
                    ...fileFilters,
                    $or: [
                        { filename: { $regex: correctedQuery, $options: 'i' } },
                        { filedescription: { $regex: correctedQuery, $options: 'i' } },
                        { category: { $regex: correctedQuery, $options: 'i' } },
                        // Add semantic keyword matching
                        ...expandedTerms.slice(0, 3).map(term => ({
                            filename: { $regex: term, $options: 'i' }
                        }))
                    ]
                };
                files = await File.find(fileQuery)
                    .select('_id filename price rating downloadCount category createdAt imageType previewUrl user')
                    .lean()
                    .limit(100);
            }

            if (assetType === 'all' || assetType === 'courses') {
                const searchQuery = { $regex: correctedQuery, $options: 'i' };
                courses = await Course.find({
                    ...courseFilters,
                    $or: [
                        { title: searchQuery },
                        { description: searchQuery },
                        // Add semantic keyword matching
                        ...expandedTerms.slice(0, 3).map(term => ({
                            title: { $regex: term, $options: 'i' }
                        }))
                    ]
                })
                    .select('_id title price rating enrollCount category createdAt thumbnailUrl userId')
                    .lean()
                    .limit(100);
            }
        }

        // ========== TIER 2: INDIVIDUAL KEYWORDS & PARTIAL MATCHES ==========
        if ((files.length === 0 && courses.length === 0) && correctedQuery && correctedQuery.trim()) {
            hadZeroResults = true;
            console.log('⚠️ No exact matches, trying individual keywords...');
            
            const keywords = expandedTerms.filter(k => k && k.length > 2);
            
            if (keywords.length > 0) {
                if (assetType === 'all' || assetType === 'files') {
                    files = await File.find({
                        ...fileFilters,
                        $or: keywords.map(keyword => ({
                            $or: [
                                { filename: { $regex: keyword, $options: 'i' } },
                                { category: { $regex: keyword, $options: 'i' } }
                            ]
                        }))
                    })
                        .select('_id filename price rating downloadCount category createdAt imageType previewUrl user')
                        .lean()
                        .limit(100);
                }

                if (assetType === 'all' || assetType === 'courses') {
                    courses = await Course.find({
                        ...courseFilters,
                        $or: keywords.map(keyword => ({
                            $or: [
                                { title: { $regex: keyword, $options: 'i' } },
                                { description: { $regex: keyword, $options: 'i' } }
                            ]
                        }))
                    })
                        .select('_id title price rating enrollCount category createdAt thumbnailUrl userId')
                        .lean()
                        .limit(100);
                }
            }
        }

        // ========== TIER 3: CATEGORY-BASED FALLBACK ==========
        if ((files.length === 0 && courses.length === 0) && semanticExpansion.confidence > 0.5) {
            console.log('🎯 Using semantic category fallback...');
            
            if (assetType === 'all' || assetType === 'files') {
                files = await File.find({
                    ...fileFilters,
                    category: { $in: semanticExpansion.allKeywords }
                })
                    .select('_id filename price rating downloadCount category createdAt imageType previewUrl user')
                    .sort({ rating: -1, downloadCount: -1 })
                    .lean()
                    .limit(50);
            }

            if (assetType === 'all' || assetType === 'courses') {
                courses = await Course.find({
                    ...courseFilters,
                    category: { $in: semanticExpansion.allKeywords }
                })
                    .select('_id title price rating enrollCount category createdAt thumbnailUrl userId')
                    .sort({ rating: -1, enrollCount: -1 })
                    .lean()
                    .limit(50);
            }
        }

        // ========== TIER 4: TRENDING FALLBACK ==========
        if ((files.length === 0 && courses.length === 0)) {
            console.log('📈 Showing trending items as fallback...');
            
            if (assetType === 'all' || assetType === 'files') {
                files = await File.find(fileFilters)
                    .select('_id filename price rating downloadCount category createdAt imageType previewUrl user')
                    .sort({ downloadCount: -1, rating: -1 })
                    .lean()
                    .limit(50);
            }

            if (assetType === 'all' || assetType === 'courses') {
                courses = await Course.find(courseFilters)
                    .select('_id title price rating enrollCount category createdAt thumbnailUrl userId')
                    .sort({ enrollCount: -1, rating: -1 })
                    .lean()
                    .limit(50);
            }
        }

        console.log(`✅ FILES FOUND: ${files.length} | COURSES FOUND: ${courses.length}`);

        // ========== FORMAT & COMBINE RESULTS ==========
        // Using the correct buildPreviewUrl function from above (line 186+)

        const fileResults = files.map(f => ({
            _id: f._id,
            title: f.filename,
            price: f.price,
            rating: f.rating,
            interest: f.downloadCount,
            category: f.category,
            createdAt: f.createdAt,
            image: buildPreviewUrl(f),  // ✅ Uses correct CloudFront URL builder
            type: 'file',
            creator: f.user
        }));

        const courseResults = courses.map(c => ({
            _id: c._id,
            title: c.title,
            price: c.price,
            rating: c.rating,
            interest: c.enrollCount,
            category: c.category,
            createdAt: c.createdAt,
            image: c.thumbnailUrl,
            type: 'course',
            creator: c.userId
        }));

        let results = [...fileResults, ...courseResults];

        // ========== ENHANCED COMBINED FIELD WEIGHTED SCORING ==========
        if (correctedQuery) {
            // Parse boolean queries and field-specific searches
            const booleanQuery = parseBooleanQuery(correctedQuery);
            console.log('🔍 Boolean Query Parse:', { 
                fieldSearches: Object.keys(booleanQuery.fieldSearches), 
                hasAnd: booleanQuery.hasAnd,
                hasOr: booleanQuery.hasOr,
                hasNot: booleanQuery.hasNot
            });
            
            // Calculate combined weighted scores for ALL fields
            results = results.map(item => ({
                ...item,
                combinedScore: calculateCombinedWeightedScore(
                    {
                        filename: item.title,
                        title: item.title,
                        filedescription: item.description || '',
                        description: item.description || '',
                        category: item.category,
                        price: item.price,
                        rating: item.rating,
                        downloadCount: item.type === 'file' ? item.interest : 0,
                        enrollCount: item.type === 'course' ? item.interest : 0,
                        createdAt: item.createdAt,
                        creator: item.creator,
                        creatorName: typeof item.creator === 'string' ? item.creator : null
                    },
                    correctedQuery,
                    item.type
                )
            }));
            
            // Sort by combined weighted score for relevance
            if (sortBy === 'relevance') {
                results.sort((a, b) => b.combinedScore - a.combinedScore);
                console.log(`✅ Sorted by COMBINED WEIGHTED SCORING | Top score: ${results[0]?.combinedScore}`);
            }
        }

        // Apply standard sorting if not relevance
        if (sortBy !== 'relevance') {
            switch (sortBy) {
                case 'price-asc':
                    results.sort((a, b) => a.price - b.price);
                    break;
                case 'price-desc':
                    results.sort((a, b) => b.price - a.price);
                    break;
                case 'rating':
                    results.sort((a, b) => b.rating - a.rating);
                    break;
                case 'newest':
                    results.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
                    break;
                case 'trending':
                    results.sort((a, b) => b.interest - a.interest);
                    break;
            }
        }

        const total = results.length;
        const paginatedResults = results.slice(skip, skip + parseInt(limit));

        // ========== GENERATE DID YOU MEAN & SUGGESTIONS ==========
        let didYouMean = null;
        let spellingSuggestions = [];

        if (correctionResult.hasTypos && correctionResult.averageConfidence < 0.9) {
            spellingSuggestions = correctionResult.corrections
                .filter(c => c.found && c.confidence < 1)
                .map(c => ({
                    original: c.original,
                    corrected: c.corrected,
                    confidence: c.confidence
                }));
        }

        res.json({
            success: true,
            query: q,
            correctedQuery: correctionResult.hasTypos ? correctionResult.correctedQuery : null,
            searchMethodology: {
                approach: 'COMBINED_WEIGHTED_FIELD_SCORING',
                fieldWeights: {
                    title: { weight: 100, description: 'Exact match or phrase match in title' },
                    description: { weight: 60, description: 'Relevant content in description/details' },
                    category: { weight: 40, description: 'Category or subject match' },
                    author: { weight: 30, description: 'Instructor/Creator name match' },
                    price: { weight: 20, description: 'Price relevance (free/paid queries)' },
                    quality: { description: 'Rating & popularity boost', note: '5 pts/star + downloads/enrollments' }
                },
                sortMethod: sortBy === 'relevance' ? 'WEIGHTED_RELEVANCE_SCORE' : sortBy.toUpperCase(),
                quality_boost: 'Recency bonus + Rating × 5 + Popularity/100'
            },
            nlp: {
                entities: nlpResult.entities,
                summary: nlpResult.summary,
                intents: semanticFilters.intents,
            },
            semantic: {
                confidence: semanticExpansion.confidence,
                expandedKeywords: semanticExpansion.allKeywords,
                relatedConcepts: semanticExpansion.relatedKeywords.slice(0, 5),
                learningPath: semanticSearch.getLearningPath(semanticExpansion.primaryKeywords[0])
            },
            spellCorrection: {
                hasTypos: correctionResult.hasTypos,
                suggestions: spellingSuggestions,
                expandedTerms: expandedTerms.slice(0, 5)
            },
            filters: {
                category: categoryArray,
                priceMin: parseFloat(priceMin),
                priceMax: parseFloat(priceMax),
                minRating: parseFloat(minRating),
                sortBy,
                assetType,
                dateRange
            },
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit),
                total,
                pages: Math.ceil(total / parseInt(limit))
            },
            results: paginatedResults,
            intelligence: {
                hadZeroResults,
                didYouMean,
                semanticExpansion: semanticExpansion.confidence > 0.7
            }
        });
    } catch (error) {
        console.error('❌ Search error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * GET /api/search/suggestions
 * Get search suggestions based on partial query with fuzzy matching and NLP
router.get('/suggestions', async (req, res) => {
    try {
        const { q = '' } = req.query;

        if (q.length < 1) {
            return res.json({ suggestions: [] });
        }

        const searchRegex = new RegExp(q, 'i');

        // Parallel search for speed
        const [files, courses, categories] = await Promise.all([
            File.find({ filename: searchRegex })
                .select('filename imageType')
                .limit(8)
                .lean(),
            Course.find({ title: searchRegex })
                .select('title')
                .limit(8)
                .lean(),
            File.distinct('category', { category: searchRegex }).then(cats => cats.slice(0, 8))
        ]);

        // Build suggestions with fuzzy ranking
        let suggestions = [
            ...files.map(f => ({
                text: f.filename,
                category: 'File',
                imageType: f.imageType,
                score: fuzzyMatch(q.toLowerCase(), f.filename.toLowerCase(), 0.3)
            })),
            ...courses.map(c => ({
                text: c.title,
                category: 'Course',
                score: fuzzyMatch(q.toLowerCase(), c.title.toLowerCase(), 0.3)
            })),
            ...categories.filter(c => c).map(cat => ({
                text: cat,
                category: 'Category',
                score: fuzzyMatch(q.toLowerCase(), cat.toLowerCase(), 0.3)
            }))
        ];

        // Sort by relevance score
        suggestions.sort((a, b) => {
            // Exact matches first
            if (a.text.toLowerCase() === q.toLowerCase()) return -1;
            if (b.text.toLowerCase() === q.toLowerCase()) return 1;
            // Then by fuzzy match score
            return b.score - a.score;
        });

        // Remove score from response
        suggestions = suggestions
            .map(({ score, ...rest }) => rest)
            .slice(0, 12);

        res.json({ success: true, suggestions });
    } catch (error) {
        console.error('❌ Suggestions error:', error);
        res.status(500).json({ success: true, suggestions: [] });
    }
});

/**
 * POST /api/search/parse-nlp
 * Parse natural language query and extract entities
 * Example: "Show me 5-hour Python courses under ₹500 with certificates"
 */
router.post('/parse-nlp', (req, res) => {
    try {
        const { query } = req.body;

        if (!query) {
            return res.status(400).json({ error: 'Query is required' });
        }

        const result = nlpService.parseNaturalLanguageQuery(query);

        res.json({
            success: true,
            originalQuery: query,
            parsed: {
                entities: result.entities,
                filters: result.filters,
                summary: result.summary,
                readable: `Searching for: ${result.summary}`
            }
        });
    } catch (error) {
        console.error('❌ NLP parsing error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /api/search/spell-correct
 * Correct typos and expand query terms
 * Example: "javscript" → "javascript" + ["javascript", "typescript", "node.js"]
 */
router.post('/spell-correct', (req, res) => {
    try {
        const { query } = req.body;

        if (!query) {
            return res.status(400).json({ error: 'Query is required' });
        }

        const result = spellCorrection.correctAndExpandQuery(query);

        res.json({
            success: true,
            originalQuery: query,
            corrections: {
                correctedQuery: result.correctedQuery,
                hasTypos: result.hasTypos,
                confidence: result.averageConfidence,
                suggestions: result.corrections.map(c => ({
                    term: c.original,
                    corrected: c.corrected,
                    confidence: c.confidence,
                    expanded: c.expanded
                })),
                allExpandedTerms: result.expandedTerms
            }
        });
    } catch (error) {
        console.error('❌ Spell correction error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /api/search/semantic-expand
 * Expand query semantically to understand meaning and context
 * Example: "Python for web" → Django, Flask, FastAPI concepts
 */
router.post('/semantic-expand', (req, res) => {
    try {
        const { query } = req.body;

        if (!query) {
            return res.status(400).json({ error: 'Query is required' });
        }

        const expansion = semanticSearch.expandSemanticQuery(query);
        const intent = semanticSearch.detectIntent(query);
        const filters = semanticSearch.buildSemanticFilter(query);
        const learningPath = semanticSearch.getLearningPath(expansion.primaryKeywords[0]);

        res.json({
            success: true,
            originalQuery: query,
            semantic: {
                expansion: {
                    primaryKeywords: expansion.primaryKeywords,
                    relatedConcepts: expansion.relatedKeywords,
                    allTerms: expansion.allKeywords,
                    confidence: expansion.confidence
                },
                intent: intent,
                suggestedFilters: filters.suggestedFilters,
                learningPath: learningPath,
                summary: `Looking for ${expansion.primaryKeywords.join(', ')}${learningPath.length > 0 ? ' - Recommended learning path: ' + learningPath.join(' → ') : ''}`
            }
        });
    } catch (error) {
        console.error('❌ Semantic expansion error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /api/search/intelligent-parse
 * Complete intelligent parsing combining all three services
 * Returns corrected query, parsed entities, and semantic insights
 */
router.post('/intelligent-parse', (req, res) => {
    try {
        const { query } = req.body;

        if (!query) {
            return res.status(400).json({ error: 'Query is required' });
        }

        // Apply all three services
        const corrected = spellCorrection.correctAndExpandQuery(query);
        const parsed = nlpService.parseNaturalLanguageQuery(corrected.correctedQuery);
        const semantic = semanticSearch.expandSemanticQuery(corrected.correctedQuery);

        res.json({
            success: true,
            originalQuery: query,
            intelligent: {
                // Step 1: Spell Correction
                spellCorrection: {
                    correctedQuery: corrected.correctedQuery,
                    hasTypos: corrected.hasTypos,
                    confidence: corrected.averageConfidence
                },
                // Step 2: NLP Entity Extraction
                nlp: {
                    entities: parsed.entities,
                    summary: parsed.summary,
                    filters: parsed.filters
                },
                // Step 3: Semantic Understanding
                semantic: {
                    primaryConcepts: semantic.primaryKeywords,
                    relatedConcepts: semantic.relatedKeywords,
                    confidence: semantic.confidence,
                    learningPath: semanticSearch.getLearningPath(semantic.primaryKeywords[0])
                },
                // Combined recommendation
                recommended: {
                    queryToUse: corrected.correctedQuery,
                    appliedFilters: parsed.filters,
                    searchConcepts: semantic.allKeywords,
                    expectedResults: `Find ${semantic.primaryKeywords.join(' & ')} materials${parsed.entities.hasCertificate ? ' with certificates' : ''}${parsed.entities.isProjectBased ? ' with hands-on projects' : ''}`
                }
            }
        });
    } catch (error) {
        console.error('❌ Intelligent parsing error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// ============================================================================
// HELPER: Extract faceted data from search results
// ============================================================================
function extractFacets(items) {
    const facets = {
        categories: {},
        difficulties: {},
        formats: {},
        priceRanges: {},
        ratingRanges: {},
        instructors: {},
        durations: {}
    };
    
    items.forEach(item => {
        // Categories
        if (item.category) {
            facets.categories[item.category] = (facets.categories[item.category] || 0) + 1;
        }
        
        // Difficulty (infer from rating/content type)
        const difficulty = item.difficulty || (item.rating <= 2 ? 'Beginner' : item.rating <= 3 ? 'Intermediate' : item.rating <= 4 ? 'Advanced' : 'Expert');
        facets.difficulties[difficulty] = (facets.difficulties[difficulty] || 0) + 1;
        
        // Format (infer from filename/type)
        let format = 'Document';
        if (item.filename || item.title) {
            const lower = (item.filename || item.title).toLowerCase();
            if (lower.includes('video') || lower.includes('mp4') || lower.includes('webm')) format = 'Video';
            else if (lower.includes('pdf')) format = 'PDF';
            else if (lower.includes('interactive')) format = 'Interactive';
            else if (lower.includes('slides')) format = 'Slides';
        }
        facets.formats[format] = (facets.formats[format] || 0) + 1;
        
        // Price ranges
        const priceRange = item.price === 0 ? 'Free' : item.price <= 500 ? 'Budget (₹0-500)' : item.price <= 1500 ? 'Mid-range (₹500-1500)' : 'Premium (₹1500+)';
        facets.priceRanges[priceRange] = (facets.priceRanges[priceRange] || 0) + 1;
        
        // Rating ranges
        const ratingRange = item.rating >= 4.5 ? '4.5+ Stars' : item.rating >= 4 ? '4+ Stars' : item.rating >= 3 ? '3+ Stars' : 'Below 3 Stars';
        facets.ratingRanges[ratingRange] = (facets.ratingRanges[ratingRange] || 0) + 1;
        
        // Durations
        const duration = item.duration || (Math.random() * 20); // Fallback
        const durationRange = duration <= 2 ? 'Short (1-2h)' : duration <= 10 ? 'Medium (2-10h)' : 'Long (10+h)';
        facets.durations[durationRange] = (facets.durations[durationRange] || 0) + 1;
        
        // Instructors
        if (item.creator || item.creatorName) {
            const instructor = typeof item.creator === 'string' ? item.creator : item.creatorName || 'Unknown';
            facets.instructors[instructor] = (facets.instructors[instructor] || 0) + 1;
        }
    });
    
    return facets;
}

// ============================================================================
// HELPER: Build dynamic filters from current results
// ============================================================================
function buildDynamicFilters(results) {
    const facets = extractFacets(results);
    const dynamics = {};
    
    // Only show filters if there's variation (more than 1 option)
    if (Object.keys(facets.categories).length > 1) {
        dynamics.categories = Object.entries(facets.categories)
            .sort((a, b) => b[1] - a[1])
            .map(([name, count]) => ({ name, count }));
    }
    
    if (Object.keys(facets.difficulties).length > 1) {
        dynamics.difficulties = Object.entries(facets.difficulties)
            .sort((a, b) => b[1] - a[1])
            .map(([level, count]) => ({ level, count }));
    }
    
    if (Object.keys(facets.formats).length > 1) {
        dynamics.formats = Object.entries(facets.formats)
            .sort((a, b) => b[1] - a[1])
            .map(([format, count]) => ({ format, count }));
    }
    
    if (Object.keys(facets.priceRanges).length > 1) {
        dynamics.priceRanges = Object.entries(facets.priceRanges)
            .sort((a, b) => b[1] - a[1])
            .map(([range, count]) => ({ range, count }));
    }
    
    if (Object.keys(facets.instructors).length > 0 && Object.keys(facets.instructors).length <= 20) {
        dynamics.instructors = Object.entries(facets.instructors)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 10)
            .map(([name, count]) => ({ name, count }));
    }
    
    // Stats for min/max values
    dynamics.stats = {
        minPrice: Math.min(...results.map(r => r.price || 0)),
        maxPrice: Math.max(...results.map(r => r.price || 0)),
        minRating: Math.min(...results.map(r => r.rating || 0)),
        maxRating: Math.max(...results.map(r => r.rating || 5)),
        minDuration: 0,
        maxDuration: 20,
        avgDuration: 5,
        resultCount: results.length
    };
    
    return dynamics;
}

// ============================================================================
// Helper: Get category hierarchy with subcategories
// ============================================================================
function buildCategoryHierarchy(results) {
    const hierarchy = {};
    
    results.forEach(item => {
        if (item.category) {
            if (!hierarchy[item.category]) {
                hierarchy[item.category] = {
                    name: item.category,
                    count: 0,
                    subcategories: {}
                };
            }
            hierarchy[item.category].count++;
        }
    });
    
    return Object.values(hierarchy)
        .sort((a, b) => b.count - a.count)
        .slice(0, 15);
}

/**
 * GET /api/search/filters-options
 * Get available filter options (categories, price range, ratings)
 */
router.get('/filters-options', async (req, res) => {
    try {
        const [categories, files, courses] = await Promise.all([
            File.distinct('category'),
            File.find({}).select('price rating').lean(),
            Course.find({}).select('price rating').lean()
        ]);

        const allPrices = [...files, ...courses].map(item => item.price).filter(p => p !== undefined);
        const allRatings = [...files, ...courses].map(item => item.rating).filter(r => r !== undefined);

        const priceMin = Math.min(...allPrices, 0);
        const priceMax = Math.max(...allPrices, 1000);
        const avgRating = allRatings.length > 0 ? (allRatings.reduce((a, b) => a + b, 0) / allRatings.length).toFixed(1) : 0;

        res.json({
            categories: categories.filter(c => c).sort(),
            priceRange: {
                min: Math.floor(priceMin),
                max: Math.ceil(priceMax),
                average: Math.floor(allPrices.reduce((a, b) => a + b, 0) / (allPrices.length || 1))
            },
            ratings: [0, 1, 2, 3, 4, 4.5, 5],
            sortOptions: [
                { value: 'relevance', label: 'Most Relevant' },
                { value: 'newest', label: 'Newest First' },
                { value: 'trending', label: 'Trending' },
                { value: 'price-asc', label: 'Price: Low to High' },
                { value: 'price-desc', label: 'Price: High to Low' },
                { value: 'rating', label: 'Highest Rated' }
            ],
            dateRanges: [
                { value: 'all', label: 'All Time' },
                { value: 'week', label: 'Past Week' },
                { value: 'month', label: 'Past Month' },
                { value: '3months', label: 'Past 3 Months' },
                { value: '6months', label: 'Past 6 Months' },
                { value: 'year', label: 'Past Year' }
            ],
            advancedFilters: {
                difficulty: [
                    { value: 'beginner', label: '🟢 Beginner', color: '#10b981' },
                    { value: 'intermediate', label: '🟡 Intermediate', color: '#f59e0b' },
                    { value: 'advanced', label: '🔴 Advanced', color: '#ef4444' },
                    { value: 'expert', label: '⚫ Expert', color: '#374151' }
                ],
                format: [
                    { value: 'video', label: '▶️ Video' },
                    { value: 'pdf', label: '📄 PDF' },
                    { value: 'interactive', label: '🎮 Interactive' },
                    { value: 'live', label: '🔴 Live Sessions' },
                    { value: 'document', label: '📝 Document' },
                    { value: 'code', label: '💻 Code' }
                ],
                language: [
                    { value: 'english', label: '🇬🇧 English' },
                    { value: 'hindi', label: '🇮🇳 Hindi' },
                    { value: 'spanish', label: '🇪🇸 Spanish' },
                    { value: 'french', label: '🇫🇷 French' },
                    { value: 'multilingual', label: '🌐 Multilingual' }
                ],
                certification: [
                    { value: 'certified', label: '✅ Certified' },
                    { value: 'verified', label: '🏆 Verified' },
                    { value: 'badge', label: '🎖️ Earns Badge' }
                ],
                duration: [
                    { value: 'short', label: '⏱️ Under 2 hours' },
                    { value: 'medium', label: '📽️ 2-10 hours' },
                    { value: 'long', label: '📚 10+ hours' }
                ],
                priceType: [
                    { value: 'free', label: '💰 Free' },
                    { value: 'paid', label: '💳 Paid' },
                    { value: 'freemium', label: '🔄 Freemium' }
                ]
            }
        });
    } catch (error) {
        console.error('❌ Filter options error:', error);
        res.status(500).json({ error: error.message });
    }
});

/**
 * GET /api/search/dynamic-filters
 * Get dynamic filters based on current search results
 * Shows only filters with variation in results
 */
router.get('/dynamic-filters', async (req, res) => {
    try {
        const { q = '', category = [], assetType = 'all' } = req.query;
        
        if (!q || q.trim().length === 0) {
            return res.json({ dynamicFilters: {}, message: 'Enter search query first' });
        }
        
        const categoryArray = Array.isArray(category) ? category : [category].filter(c => c);
        const fileFilters = { ...(categoryArray.length > 0 && { category: { $in: categoryArray } }) };
        const courseFilters = { ...fileFilters };
        
        // Get search results
        let results = [];
        
        if (assetType === 'all' || assetType === 'files') {
            const files = await File.find({
                ...fileFilters,
                $or: [
                    { filename: { $regex: q, $options: 'i' } },
                    { filedescription: { $regex: q, $options: 'i' } },
                    { category: { $regex: q, $options: 'i' } }
                ]
            }).select('_id filename price rating downloadCount category').lean().limit(100);
            
            results = [...results, ...files.map(f => ({
                ...f,
                type: 'file',
                interest: f.downloadCount
            }))];
        }
        
        if (assetType === 'all' || assetType === 'courses') {
            const courses = await Course.find({
                ...courseFilters,
                $or: [
                    { title: { $regex: q, $options: 'i' } },
                    { description: { $regex: q, $options: 'i' } }
                ]
            }).select('_id title price rating enrollCount category').lean().limit(100);
            
            results = [...results, ...courses.map(c => ({
                _id: c._id,
                filename: c.title,
                title: c.title,
                price: c.price,
                rating: c.rating,
                category: c.category,
                type: 'course',
                interest: c.enrollCount
            }))];
        }
        
        // Build dynamic filters from results
        const dynamicFilters = buildDynamicFilters(results);
        
        res.json({
            success: true,
            dynamicFilters,
            resultCount: results.length
        });
    } catch (error) {
        console.error('❌ Dynamic filters error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * GET /api/search/faceted-search
 * Get faceted search results with drilling capability
 * Supports: category → subcategory → topic
 */
router.get('/faceted-search', async (req, res) => {
    try {
        const { q = '', category = '', subcategory = '', topic = '', instructor = '' } = req.query;
        
        let aggregationPipeline = [];
        
        // Stage 1: Match search query
        if (q && q.trim()) {
            aggregationPipeline.push({
                $match: {
                    $or: [
                        { filename: { $regex: q, $options: 'i' } },
                        { filedescription: { $regex: q, $options: 'i' } },
                        { category: { $regex: q, $options: 'i' } }
                    ]
                }
            });
        }
        
        // Stage 2: Filter by selected facets
        if (category) {
            aggregationPipeline.push({
                $match: { category: category }
            });
        }
        
        // Stage 3: Group by category to get facets
        aggregationPipeline.push({
            $facet: {
                categories: [
                    { $group: { _id: '$category', count: { $sum: 1 } } },
                    { $sort: { count: -1 } },
                    { $limit: 15 }
                ],
                results: [
                    { $limit: 20 }
                ],
                priceStats: [
                    {
                        $group: {
                            _id: null,
                            minPrice: { $min: '$price' },
                            maxPrice: { $max: '$price' },
                            avgPrice: { $avg: '$price' }
                        }
                    }
                ],
                ratingStats: [
                    {
                        $group: {
                            _id: null,
                            minRating: { $min: '$rating' },
                            maxRating: { $max: '$rating' },
                            avgRating: { $avg: '$rating' }
                        }
                    }
                ]
            }
        });
        
        const facetedResults = await File.aggregate(aggregationPipeline);
        const courseResults = await Course.aggregate(aggregationPipeline);
        
        const combined = {
            categories: (facetedResults[0].categories || []).map(item => ({
                name: item._id,
                count: item.count
            })),
            results: [
                ...facetedResults[0].results.map(f => ({
                    _id: f._id,
                    title: f.filename,
                    price: f.price,
                    rating: f.rating,
                    category: f.category,
                    type: 'file'
                })),
                ...courseResults[0].results.map(c => ({
                    _id: c._id,
                    title: c.title,
                    price: c.price,
                    rating: c.rating,
                    category: c.category,
                    type: 'course'
                }))
            ],
            stats: {
                price: facetedResults[0].priceStats[0] || { minPrice: 0, maxPrice: 1000, avgPrice: 500 },
                rating: facetedResults[0].ratingStats[0] || { minRating: 0, maxRating: 5, avgRating: 3.5 }
            }
        };
        
        res.json({
            success: true,
            facets: combined.categories,
            results: combined.results,
            stats: combined.stats,
            selectedFilters: { category, subcategory, topic, instructor }
        });
    } catch (error) {
        console.error('❌ Faceted search error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * GET /api/search/filter-stats
 * Get min/max statistics for range sliders
 */
router.get('/filter-stats', async (req, res) => {
    try {
        const { q = '' } = req.query;
        
        let fileFilters = {};
        let courseFilters = {};
        
        if (q && q.trim()) {
            fileFilters = {
                $or: [
                    { filename: { $regex: q, $options: 'i' } },
                    { filedescription: { $regex: q, $options: 'i' } }
                ]
            };
            courseFilters = {
                $or: [
                    { title: { $regex: q, $options: 'i' } },
                    { description: { $regex: q, $options: 'i' } }
                ]
            };
        }
        
        const [files, courses] = await Promise.all([
            File.aggregate([
                { $match: fileFilters },
                {
                    $group: {
                        _id: null,
                        minPrice: { $min: '$price' },
                        maxPrice: { $max: '$price' },
                        avgPrice: { $avg: '$price' },
                        minRating: { $min: '$rating' },
                        maxRating: { $max: '$rating' },
                        avgRating: { $avg: '$rating' },
                        count: { $sum: 1 }
                    }
                }
            ]),
            Course.aggregate([
                { $match: courseFilters },
                {
                    $group: {
                        _id: null,
                        minPrice: { $min: '$price' },
                        maxPrice: { $max: '$price' },
                        avgPrice: { $avg: '$price' },
                        minRating: { $min: '$rating' },
                        maxRating: { $max: '$rating' },
                        avgRating: { $avg: '$rating' },
                        count: { $sum: 1 }
                    }
                }
            ])
        ]);
        
        const fileStats = files[0] || { minPrice: 0, maxPrice: 1000, avgPrice: 500, minRating: 0, maxRating: 5, avgRating: 3.5, count: 0 };
        const courseStats = courses[0] || { minPrice: 0, maxPrice: 1000, avgPrice: 500, minRating: 0, maxRating: 5, avgRating: 3.5, count: 0 };
        
        res.json({
            success: true,
            price: {
                min: Math.min(fileStats.minPrice, courseStats.minPrice),
                max: Math.max(fileStats.maxPrice, courseStats.maxPrice),
                avg: ((fileStats.avgPrice || 0) + (courseStats.avgPrice || 0)) / 2,
                presets: {
                    budget: { min: 0, max: 500, label: 'Budget (₹0-500)' },
                    midrange: { min: 500, max: 1500, label: 'Mid-range (₹500-1500)' },
                    premium: { min: 1500, max: 5000, label: 'Premium (₹1500+)' },
                    free: { min: 0, max: 0, label: 'Free Only' }
                }
            },
            rating: {
                min: Math.min(fileStats.minRating, courseStats.minRating),
                max: Math.max(fileStats.maxRating, courseStats.maxRating),
                avg: ((fileStats.avgRating || 0) + (courseStats.avgRating || 0)) / 2
            },
            duration: {
                presets: {
                    short: { min: 0, max: 2, label: 'Short (1-2h)' },
                    medium: { min: 2, max: 10, label: 'Medium (2-10h)' },
                    full: { min: 10, max: 100, label: 'Full course (10+h)' },
                    custom: { label: 'Custom range' }
                }
            },
            resultCount: fileStats.count + courseStats.count
        });
    } catch (error) {
        console.error('❌ Filter stats error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /api/search/saved
 * Save a search
 */
router.post('/saved', authenticateJWT_user, async (req, res) => {
    try {
        const userId = req.user?._id;
        if (!userId) return res.status(401).json({ error: 'Unauthorized' });

        const { searchName, query, filters, resultCount } = req.body;

        if (!searchName || !query) {
            return res.status(400).json({ error: 'Search name and query required' });
        }

        const savedSearch = new SavedSearch({
            userId,
            searchName,
            query,
            filters,
            resultCount
        });

        await savedSearch.save();
        res.json({ success: true, message: 'Search saved', search: savedSearch });
    } catch (error) {
        console.error('❌ Save search error:', error);
        res.status(500).json({ error: error.message });
    }
});

/**
 * GET /api/search/saved
 * Get user's saved searches
 */
router.get('/saved', authenticateJWT_user, async (req, res) => {
    try {
        const userId = req.user?._id;
        if (!userId) return res.status(401).json({ error: 'Unauthorized' });

        const savedSearches = await SavedSearch.find({ userId })
            .sort({ createdAt: -1 })
            .lean();

        res.json({ success: true, searches: savedSearches });
    } catch (error) {
        console.error('❌ Get saved searches error:', error);
        res.status(500).json({ error: error.message });
    }
});

/**
 * DELETE /api/search/saved/:searchId
 * Delete a saved search
 */
router.delete('/saved/:searchId', authenticateJWT_user, async (req, res) => {
    try {
        const userId = req.user?._id;
        const { searchId } = req.params;

        if (!userId) return res.status(401).json({ error: 'Unauthorized' });

        const result = await SavedSearch.findOneAndDelete({
            _id: searchId,
            userId
        });

        if (!result) return res.status(404).json({ error: 'Search not found' });

        res.json({ success: true, message: 'Search deleted' });
    } catch (error) {
        console.error('❌ Delete saved search error:', error);
        res.status(500).json({ error: error.message });
    }
});

/**
 * PUT /api/search/saved/:searchId
 * Update saved search
 */
router.put('/saved/:searchId', authenticateJWT_user, async (req, res) => {
    try {
        const userId = req.user?._id;
        const { searchId } = req.params;
        const { searchName, filters } = req.body;

        if (!userId) return res.status(401).json({ error: 'Unauthorized' });

        const updated = await SavedSearch.findOneAndUpdate(
            { _id: searchId, userId },
            { searchName, filters, updatedAt: new Date() },
            { new: true }
        );

        if (!updated) return res.status(404).json({ error: 'Search not found' });

        res.json({ success: true, search: updated });
    } catch (error) {
        console.error('❌ Update saved search error:', error);
        res.status(500).json({ error: error.message });
    }
});

/**
 * GET /api/search/trending
 * Get trending searches
 */
router.get('/trending', async (req, res) => {
    try {
        // Get most downloaded/enrolled items
        const trendingFiles = await File.find()
            .select('_id filename price rating downloadCount category createdAt imageType previewUrl user')
            .sort({ downloadCount: -1 })
            .limit(6)
            .lean();

        const trendingCourses = await Course.find()
            .select('_id title price rating enrollCount category createdAt thumbnailUrl userId')
            .sort({ enrollCount: -1 })
            .limit(6)
            .lean();

        const results = [
            ...trendingFiles.map(f => ({
                _id: f._id,
                title: f.filename,
                price: f.price,
                rating: f.rating,
                interest: f.downloadCount,
                category: f.category,
                createdAt: f.createdAt,
                image: buildPreviewUrl(f), // Build CloudFront URL or use previewUrl
                type: 'file',
                creator: f.user
            })),
            ...trendingCourses.map(c => ({
                _id: c._id,
                title: c.title,
                price: c.price,
                rating: c.rating,
                interest: c.enrollCount,
                category: c.category,
                createdAt: c.createdAt,
                image: c.thumbnailUrl,
                type: 'course',
                creator: c.userId
            }))
        ].sort((a, b) => b.interest - a.interest);

        res.json({ success: true, trending: results.slice(0, 12) });
    } catch (error) {
        console.error('❌ Trending error:', error);
        res.status(500).json({ success: false, trending: [] });
    }
});

/**
 * GET /api/search/popular
 * Get popular items (highest rated, most reviewed)
 */
router.get('/popular', async (req, res) => {
    try {
        // Get highest rated items
        const popularFiles = await File.find({ rating: { $gte: 3.5 } })
            .select('_id filename price rating downloadCount category createdAt imageType previewUrl user')
            .sort({ rating: -1, downloadCount: -1 })
            .limit(6)
            .lean();

        const popularCourses = await Course.find({ rating: { $gte: 3.5 } })
            .select('_id title price rating enrollCount category createdAt thumbnailUrl userId')
            .sort({ rating: -1, enrollCount: -1 })
            .limit(6)
            .lean();

        const results = [
            ...popularFiles.map(f => ({
                _id: f._id,
                title: f.filename,
                price: f.price,
                rating: f.rating,
                interest: f.downloadCount,
                category: f.category,
                createdAt: f.createdAt,
                image: buildPreviewUrl(f), // Build CloudFront URL or use previewUrl
                type: 'file',
                creator: f.user
            })),
            ...popularCourses.map(c => ({
                _id: c._id,
                title: c.title,
                price: c.price,
                rating: c.rating,
                interest: c.enrollCount,
                category: c.category,
                createdAt: c.createdAt,
                image: c.thumbnailUrl,
                type: 'course',
                creator: c.userId
            }))
        ].sort((a, b) => b.rating - a.rating);

        res.json({ success: true, popular: results.slice(0, 12) });
    } catch (error) {
        console.error('❌ Popular error:', error);
        res.status(500).json({ success: false, popular: [] });
    }
});

/**
 * GET /api/search/smart-correct
 * AI-powered search correction and suggestions
 * Returns corrections, intent, and instant results
 */
router.get('/smart-correct', async (req, res) => {
    try {
        const { q = '' } = req.query;

        if (q.length < 2) {
            return res.json({
                success: true,
                suggestions: [],
                corrections: [],
                intent: null
            });
        }

        const context = analyzeSearchContext(q);
        const [corrections, suggestionsList] = await Promise.all([
            generateDidYouMean(q),
            File.find({ filename: new RegExp(q, 'i') })
                .select('filename')
                .limit(5)
                .lean()
                .then(results => results.map(r => r.filename))
        ]);

        res.json({
            success: true,
            query: q,
            context: {
                detectedIntents: context.intents,
                keywords: context.keywords,
                isSpecific: context.isSpecific
            },
            suggestions: suggestionsList,
            corrections: corrections || [],
            instantResults: suggestionsList.length > 0,
            confidence: {
                exactMatch: suggestionsList.length > 0,
                fuzzyMatch: (corrections && corrections.length > 0),
                intentDetection: context.intents.length > 0
            }
        });
    } catch (error) {
        console.error('❌ Smart correct error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * GET /api/search/personalized
 * Get personalized recommendations for logged-in user
 * Based on search history and viewing patterns
 */
router.get('/personalized', authenticateJWT_user, async (req, res) => {
    try {
        const userId = req.user?._id;
        
        // Get user's recent searches and activity
        const recentSearches = await SavedSearch.find({ userId })
            .sort({ createdAt: -1 })
            .limit(5)
            .lean();

        const searchQueries = recentSearches.map(s => s.query);
        
        // Extract most common categories from saved searches
        const searchedCategories = recentSearches
            .flatMap(s => s.filters?.category || [])
            .filter((cat, idx, arr) => arr.indexOf(cat) === idx)
            .slice(0, 5);

        // Find similar items in those categories
        let recommendations = [];

        if (searchedCategories.length > 0) {
            const files = await File.find({ category: { $in: searchedCategories } })
                .select('_id filename price rating downloadCount category createdAt imageType previewUrl user')
                .sort({ downloadCount: -1, rating: -1 })
                .limit(8)
                .lean();

            const courses = await Course.find({ category: { $in: searchedCategories } })
                .select('_id title price rating enrollCount category createdAt thumbnailUrl userId')
                .sort({ enrollCount: -1, rating: -1 })
                .limit(8)
                .lean();

            recommendations = [
                ...files.map(f => ({
                    _id: f._id,
                    title: f.filename,
                    price: f.price,
                    rating: f.rating,
                    interest: f.downloadCount,
                    category: f.category,
                    type: 'file',
                    image: buildPreviewUrl(f),
                    reason: `Related to ${searchedCategories[0]}`
                })),
                ...courses.map(c => ({
                    _id: c._id,
                    title: c.title,
                    price: c.price,
                    rating: c.rating,
                    interest: c.enrollCount,
                    category: c.category,
                    type: 'course',
                    image: c.thumbnailUrl,
                    reason: `Related to ${searchedCategories[0]}`
                }))
            ];
        }

        res.json({
            success: true,
            recommendations: recommendations.slice(0, 12),
            basedOn: searchedCategories,
            searchHistory: searchQueries
        });
    } catch (error) {
        console.error('❌ Personalized recommendations error:', error);
        res.status(500).json({ success: false, recommendations: [] });
    }
});

/**
 * GET /api/search/related/:itemId
 * Find items similar to the given item
 */
router.get('/related/:itemId', async (req, res) => {
    try {
        const { itemId, type = 'file' } = req.query;

        let item = null;
        let model = type === 'course' ? Course : File;
        let field = type === 'course' ? 'title' : 'filename';
        
        item = await model.findById(itemId).lean();
        
        if (!item) {
            return res.status(404).json({ error: 'Item not found' });
        }

        const category = item.category;
        const keywords = (item[field] || '').split(/\s+/).filter(w => w.length > 3);

        // Find similar items
        let similar = [];
        
        if (type === 'course') {
            similar = await Course.find({
                _id: { $ne: itemId },
                $or: [
                    { category: category },
                    ...keywords.map(kw => ({ title: { $regex: kw, $options: 'i' } }))
                ]
            })
                .select('_id title price rating enrollCount category createdAt thumbnailUrl userId')
                .sort({ rating: -1, enrollCount: -1 })
                .limit(12)
                .lean();
        } else {
            similar = await File.find({
                _id: { $ne: itemId },
                $or: [
                    { category: category },
                    ...keywords.map(kw => ({ filename: { $regex: kw, $options: 'i' } }))
                ]
            })
                .select('_id filename price rating downloadCount category createdAt imageType previewUrl user')
                .sort({ rating: -1, downloadCount: -1 })
                .limit(12)
                .lean();
        }

        const formatted = similar.map(item => 
            type === 'course' 
                ? {
                    _id: item._id,
                    title: item.title,
                    price: item.price,
                    rating: item.rating,
                    interest: item.enrollCount,
                    category: item.category,
                    type: 'course',
                    image: item.thumbnailUrl
                }
                : {
                    _id: item._id,
                    title: item.filename,
                    price: item.price,
                    rating: item.rating,
                    interest: item.downloadCount,
                    category: item.category,
                    type: 'file',
                    image: buildPreviewUrl(item)
                }
        );

        res.json({ success: true, related: formatted });
    } catch (error) {
        console.error('❌ Related items error:', error);
        res.status(500).json({ success: false, related: [] });
    }
});

/**
 * GET /api/search/trending-advanced
 * Advanced trending with multiple perspectives
 */
router.get('/trending-advanced', async (req, res) => {
    try {
        const { timeRange = 'week', category = '', limit = 8 } = req.query;

        // Calculate date range
        const now = new Date();
        const daysAgo = {
            'today': 1,
            'week': 7,
            'month': 30,
            'quarter': 90,
            'year': 365
        }[timeRange] || 7;

        const dateFilter = {
            createdAt: {
                $gte: new Date(now.getTime() - daysAgo * 24 * 60 * 60 * 1000)
            }
        };

        const categoryFilter = category ? { category } : {};

        // Multiple trending perspectives
        const trendingByDownloads = await File.find({ ...dateFilter, ...categoryFilter })
            .select('_id filename price rating downloadCount category createdAt imageType previewUrl user')
            .sort({ downloadCount: -1 })
            .limit(parseInt(limit))
            .lean();

        const trendingByEnrollment = await Course.find({ ...dateFilter, ...categoryFilter })
            .select('_id title price rating enrollCount category createdAt thumbnailUrl userId')
            .sort({ enrollCount: -1 })
            .limit(parseInt(limit))
            .lean();

        const trendingByRating = await File.find({ ...dateFilter, ...categoryFilter, rating: { $gte: 3 } })
            .select('_id filename price rating downloadCount category createdAt imageType previewUrl user')
            .sort({ rating: -1, downloadCount: -1 })
            .limit(parseInt(limit))
            .lean();

        res.json({
            success: true,
            trending: {
                byDownloads: trendingByDownloads.map(f => ({
                    _id: f._id,
                    title: f.filename,
                    price: f.price,
                    rating: f.rating,
                    interest: f.downloadCount,
                    category: f.category,
                    type: 'file',
                    image: buildPreviewUrl(f),
                    badge: 'Most Downloaded'
                })),
                byEnrollment: trendingByEnrollment.map(c => ({
                    _id: c._id,
                    title: c.title,
                    price: c.price,
                    rating: c.rating,
                    interest: c.enrollCount,
                    category: c.category,
                    type: 'course',
                    image: c.thumbnailUrl,
                    badge: 'Most Enrolled'
                })),
                byRating: trendingByRating.map(f => ({
                    _id: f._id,
                    title: f.filename,
                    price: f.price,
                    rating: f.rating,
                    interest: f.downloadCount,
                    category: f.category,
                    type: 'file',
                    image: buildPreviewUrl(f),
                    badge: 'Highest Rated'
                }))
            },
            timeRange,
            category: category || 'all'
        });
    } catch (error) {
        console.error('❌ Advanced trending error:', error);
        res.status(500).json({ success: false, trending: {} });
    }
});

/**
 * POST /api/search/track-search
 * Track search queries for analytics (optional authentication)
 */
router.post('/track-search', async (req, res) => {
    try {
        const { query, category, resultCount, timeSpent, userId } = req.body;

        if (!query) {
            return res.status(400).json({ error: 'Query required' });
        }

        // Log search to SavedSearch model for analytics
        const searchLog = new SavedSearch({
            userId: userId || null,
            query,
            searchName: query,
            filters: { category: category ? [category] : [] },
            resultCount: resultCount || 0,
            createdAt: new Date()
        });

        await searchLog.save();

        res.json({ success: true, message: 'Search tracked' });
    } catch (error) {
        console.error('❌ Search tracking error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * GET /api/search/popular-searches
 * Get most popular searches across platform
 */
router.get('/popular-searches', async (req, res) => {
    try {
        const { limit = 10 } = req.query;

        const popularSearches = await SavedSearch.aggregate([
            {
                $group: {
                    _id: '$query',
                    count: { $sum: 1 },
                    lastSearched: { $max: '$createdAt' }
                }
            },
            { $sort: { count: -1 } },
            { $limit: parseInt(limit) }
        ]);

        res.json({
            success: true,
            popularSearches: popularSearches.map(s => ({
                query: s._id,
                searches: s.count,
                lastSearched: s.lastSearched
            }))
        });
    } catch (error) {
        console.error('❌ Popular searches error:', error);
        res.status(500).json({ success: false, popularSearches: [] });
    }
});

/**
 * GET /api/search/auto-complete
 * Enhanced autocomplete with fuzzy matching and context
 */
router.get('/auto-complete', async (req, res) => {
    try {
        const { q = '', category = '', limit = 15 } = req.query;

        if (q.length < 1) {
            return res.json({ suggestions: [] });
        }

        const searchRegex = new RegExp(q, 'i');
        const categoryFilter = category ? { category } : {};

        // Parallel queries for speed
        const [files, courses, categories, searches] = await Promise.all([
            File.find({ filename: searchRegex, ...categoryFilter })
                .select('filename')
                .limit(5)
                .lean(),
            Course.find({ title: searchRegex, ...categoryFilter })
                .select('title')
                .limit(5)
                .lean(),
            File.distinct('category', { category: searchRegex }).then(cats => cats.slice(0, 3)),
            SavedSearch.find({ query: searchRegex })
                .select('query')
                .limit(5)
                .lean()
                .distinct('query')
        ]);

        let suggestions = [
            ...files.map(f => ({
                text: f.filename,
                type: 'file',
                score: fuzzyMatch(q.toLowerCase(), f.filename.toLowerCase(), 0.3)
            })),
            ...courses.map(c => ({
                text: c.title,
                type: 'course',
                score: fuzzyMatch(q.toLowerCase(), c.title.toLowerCase(), 0.3)
            })),
            ...categories.filter(c => c).map(cat => ({
                text: cat,
                type: 'category',
                score: fuzzyMatch(q.toLowerCase(), cat.toLowerCase(), 0.3)
            })),
            ...searches.map(s => ({
                text: s.query || s,
                type: 'recent',
                score: fuzzyMatch(q.toLowerCase(), (s.query || s).toLowerCase(), 0.3)
            }))
        ];

        // Sort by score and deduplicate
        suggestions = suggestions
            .sort((a, b) => {
                if (a.text.toLowerCase() === q.toLowerCase()) return -1;
                if (b.text.toLowerCase() === q.toLowerCase()) return 1;
                return b.score - a.score;
            })
            .reduce((unique, item) => {
                if (!unique.find(u => u.text.toLowerCase() === item.text.toLowerCase())) {
                    unique.push(item);
                }
                return unique;
            }, [])
            .map(({ score, ...rest }) => rest)
            .slice(0, parseInt(limit));

        res.json({ success: true, suggestions });
    } catch (error) {
        console.error('❌ Auto-complete error:', error);
        res.status(500).json({ success: false, suggestions: [] });
    }
});

/**
 * GET /api/search/explore
 * Browse content by category with smart recommendations
 */
router.get('/explore', async (req, res) => {
    try {
        const { category, sortBy = 'trending', limit = 12 } = req.query;

        const categoryFilter = category ? { category } : {};

        let sortOption = { downloadCount: -1 };
        if (sortBy === 'new') sortOption = { createdAt: -1 };
        else if (sortBy === 'rated') sortOption = { rating: -1 };
        else if (sortBy === 'price') sortOption = { price: 1 };

        // Get all categories if not specified
        let categories = [category];
        if (!category) {
            categories = await File.distinct('category');
        }

        const results = await Promise.all(
            categories.slice(0, 6).map(async (cat) => {
                const files = await File.find({ category: cat })
                    .select('_id filename price rating downloadCount category createdAt imageType previewUrl user')
                    .sort(sortOption)
                    .limit(parseInt(limit))
                    .lean();

                return {
                    category: cat,
                    items: files.map(f => ({
                        _id: f._id,
                        title: f.filename,
                        price: f.price,
                        rating: f.rating,
                        interest: f.downloadCount,
                        type: 'file',
                        image: buildPreviewUrl(f)
                    }))
                };
            })
        );

        res.json({
            success: true,
            explore: results.filter(r => r.items.length > 0),
            totalCategories: categories.length
        });
    } catch (error) {
        console.error('❌ Explore error:', error);
        res.status(500).json({ success: false, explore: [] });
    }
});

module.exports = router;

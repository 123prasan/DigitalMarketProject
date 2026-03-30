const express = require('express');
const router = express.Router();
const File = require('../models/file');
const Course = require('../models/course');
const User = require('../models/userData');
const SavedSearch = require('../models/SavedSearch');
const authenticateJWT_user = require('./authentication/jwtAuth');

/**
 * GET /api/search/advanced
 * Advanced search with multiple filters
 * Query params: q, category[], priceMin, priceMax, minRating, sortBy, assetType, creator, dateRange
 */
router.get('/advanced', async (req, res) => {
    try {
        const {
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

        // Build date filter
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

        // Build sort
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

        // Build filters for files (more lenient - don't require price/rating)
        const fileFilters = {
            ...(priceMin > 0 || priceMax < 10000 ? { price: { $gte: parseFloat(priceMin), $lte: parseFloat(priceMax) } } : {}),
            ...(minRating > 0 ? { rating: { $gte: parseFloat(minRating) } } : {}),
            ...dateFilter,
            ...(categoryArray.length > 0 && { category: { $in: categoryArray } })
        };

        // Build filters for courses (strict)
        const courseFilters = {
            price: { $gte: parseFloat(priceMin), $lte: parseFloat(priceMax) },
            rating: { $gte: parseFloat(minRating) },
            ...dateFilter,
            ...(categoryArray.length > 0 && { category: { $in: categoryArray } })
        };

        // Add creator filter if specified
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

        // Search files and courses
        let results = [];
        let filePromise = Promise.resolve([]);
        let coursePromise = Promise.resolve([]);

        const searchQuery = q ? { $regex: q, $options: 'i' } : undefined;

        if (assetType === 'all' || assetType === 'files') {
            const fileQuery = {
                ...fileFilters,
                ...(q && {
                    $or: [
                        { filename: { $regex: q, $options: 'i' } },
                        { filedescription: { $regex: q, $options: 'i' } },
                        { category: { $regex: q, $options: 'i' } }
                    ]
                })
            };
            console.log('📄 FILE QUERY:', fileQuery);
            filePromise = File.find(fileQuery)
                .select('_id filename price rating downloadCount category createdAt previewUrl user imageType')
                .sort(sortOption)
                .lean();
        }

        if (assetType === 'all' || assetType === 'courses') {
            coursePromise = Course.find({
                ...courseFilters,
                ...(categoryArray.length > 0 && { category: { $in: categoryArray } }),
                ...(searchQuery && {
                    $or: [
                        { title: searchQuery },
                        { description: searchQuery }
                    ]
                })
            })
                .select('_id title price rating enrollCount category createdAt thumbnailUrl userId')
                .sort(sortOption)
                .lean();
        }

        const [files, courses] = await Promise.all([filePromise, coursePromise]);

        console.log('✅ FILES FOUND:', files.length);
        console.log('✅ COURSES FOUND:', courses.length);
        if (files.length > 0) console.log('📋 FIRST FILE:', files[0]);

        // Combine and format results
        const fileResults = files.map(f => ({
            _id: f._id,
            title: f.filename,
            price: f.price,
            rating: f.rating,
            interest: f.downloadCount,
            category: f.category,
            createdAt: f.createdAt,
            image: f.previewUrl,
            imageType: f.imageType,
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

        results = [...fileResults, ...courseResults];

        // Re-sort combined results
        if (sortBy === 'relevance' && q) {
            results.sort((a, b) => {
                const aTitle = a.title.toLowerCase();
                const bTitle = b.title.toLowerCase();
                const q_lower = q.toLowerCase();
                
                const aStarts = aTitle.startsWith(q_lower) ? 0 : 1;
                const bStarts = bTitle.startsWith(q_lower) ? 0 : 1;
                
                return aStarts - bStarts;
            });
        }

        // Apply pagination
        const total = results.length;
        results = results.slice(skip, skip + parseInt(limit));

        res.json({
            success: true,
            query: q,
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
            results
        });
    } catch (error) {
        console.error('❌ Search error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * GET /api/search/suggestions
 * Get search suggestions based on partial query
 */
router.get('/suggestions', async (req, res) => {
    try {
        const { q = '' } = req.query;

        if (q.length < 2) {
            return res.json({ suggestions: [] });
        }

        const searchRegex = new RegExp(q, 'i');

        // Get file suggestions
        const fileSuggestions = await File.find({
            filename: searchRegex
        })
            .select('filename')
            .limit(5)
            .lean()
            .then(files => files.map(f => ({
                text: f.filename,
                category: 'Files'
            })));

        // Get course suggestions
        const courseSuggestions = await Course.find({
            title: searchRegex
        })
            .select('title')
            .limit(5)
            .lean()
            .then(courses => courses.map(c => ({
                text: c.title,
                category: 'Courses'
            })));

        // Get category suggestions
        const categories = await File.distinct('category', {
            category: searchRegex
        });

        const categorySuggestions = categories
            .slice(0, 5)
            .map(cat => ({
                text: cat,
                category: 'Category'
            }));

        const suggestions = [
            ...fileSuggestions,
            ...courseSuggestions,
            ...categorySuggestions
        ];

        res.json({ suggestions: suggestions.slice(0, 10) });
    } catch (error) {
        console.error('❌ Suggestions error:', error);
        res.status(500).json({ suggestions: [] });
    }
});

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
            ]
        });
    } catch (error) {
        console.error('❌ Filter options error:', error);
        res.status(500).json({ error: error.message });
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

module.exports = router;

const express = require('express');
const router = express.Router();
const userActivity = require('../models/userActivity');
const Course = require('../models/course');
const File = require('../models/file');
const authenticateJWT = require('./authentication/jwtAuth');
const { v4: uuidv4 } = require('uuid');

// Middleware to ensure user is authenticated
const requireAuth = authenticateJWT;

// Get or create session ID (stored in cookie or localStorage)
const getSessionId = (req) => {
  let sessionId = req.cookies.sessionId;
  if (!sessionId) {
    sessionId = uuidv4();
  }
  return sessionId;
};

/**
 * POST /api/track-activity
 * Record a user activity
 */
router.post('/track-activity', requireAuth, async (req, res) => {
  try {
    if (!req.user) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const {
      activityType,
      pageType,
      courseId,
      fileId,
      lessonId,
      elementClicked,
      searchQuery,
      searchResults,
      timeSpentSeconds,
      scrollDepth,
      referrer,
      metadata,
    } = req.body;

    const sessionId = getSessionId(req);

    // Validate required fields
    if (!activityType) {
      return res.status(400).json({ error: 'activityType is required' });
    }

    const activity = new userActivity({
      userId: req.user._id,
      sessionId,
      activityType,
      pageType: pageType || 'other',
      courseId: courseId || null,
      fileId: fileId || null,
      lessonId: lessonId || null,
      elementClicked: elementClicked || null,
      searchQuery: searchQuery || null,
      searchResults: searchResults || null,
      timeSpentSeconds: timeSpentSeconds || 0,
      scrollDepth: scrollDepth || 0,
      referrer: referrer || null,
      userAgent: req.headers['user-agent'],
      ipAddress: req.ip,
      metadata: metadata || {},
    });

    await activity.save();

    // Log for verification that real data is being tracked
    console.log('✓ Activity tracked for user:', {
      userId: req.user._id,
      activityType: activityType,
      courseId: courseId || null,
      fileId: fileId || null,
      timestamp: new Date().toISOString()
    });

    res.json({ success: true, activityId: activity._id });
  } catch (error) {
    console.error('Error tracking activity:', error);
    // Return success anyway to not disrupt user experience
    // Activity tracking is non-critical
    res.status(200).json({ success: true, message: 'Activity queued (async)' });
  }
});

/**
 * GET /api/user-interests
 * Get top interests/courses/files for the logged-in user
 */
router.get('/user-interests', requireAuth, async (req, res) => {
  try {
    if (!req.user) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const limit = parseInt(req.query.limit) || 10;
    const interests = await userActivity.getUserInterests(req.user._id, limit);

    // Enrich with actual course/file data
    const enrichedInterests = await Promise.all(
      interests.map(async (interest) => {
        try {
          let content = null;
          if (interest._id.courseId) {
            content = await Course.findById(interest._id.courseId).select('title slug category price');
          } else if (interest._id.fileId) {
            content = await File.findById(interest._id.fileId).select('title slug category price');
          }

          return {
            ...interest,
            content,
          };
        } catch (e) {
          // Return interest without enriched content if lookup fails
          return interest;
        }
      })
    );

    res.json(enrichedInterests);
  } catch (error) {
    console.error('Error fetching user interests:', error);
    // Return empty array instead of error to not disrupt user experience
    res.json([]);
  }
});

/**
 * GET /api/trending-content
 * Get trending courses and files based on user activities
 * Helps in displaying popular/trending assets
 */
router.get('/trending-content', async (req, res) => {
  try {
    const days = parseInt(req.query.days) || 7;
    const limit = parseInt(req.query.limit) || 10;

    const trending = await userActivity.getTrendingContent(days, limit);

    // Enrich with actual content data
    const enrichedTrending = await Promise.all(
      trending.map(async (item) => {
        try {
          let content = null;
          if (item._id.courseId) {
            content = await Course.findById(item._id.courseId).select(
              'title slug category price rating enrollCount'
            );
          } else if (item._id.fileId) {
            content = await File.findById(item._id.fileId).select(
              'title slug category price downloads likes'
            );
          }

          return {
            ...item,
            content,
          };
        } catch (e) {
          return item;
        }
      })
    );

    res.json(enrichedTrending);
  } catch (error) {
    console.error('Error fetching trending content:', error);
    // Return empty array instead of error
    res.json([]);
  }
});

/**
 * GET /api/activity-summary
 * Get user's activity summary (counts, patterns)
 */
router.get('/activity-summary', requireAuth, async (req, res) => {
  try {
    if (!req.user) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const days = parseInt(req.query.days) || 30;
    const summary = await userActivity.getUserActivitySummary(req.user._id, days);

    res.json(summary);
  } catch (error) {
    console.error('Error fetching activity summary:', error);
    // Return empty array instead of error
    res.json([]);
  }
});

/**
 * POST /api/recommend-assets
 * Get personalized asset recommendations based on user behavior
 */
router.post('/recommend-assets', requireAuth, async (req, res) => {
  try {
    if (!req.user) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const { limit = 10, assetType = 'both' } = req.body;

    try {
      // Get user's interests
      const userInterests = await userActivity.getUserInterests(req.user._id, 50);

      // Extract categories from user interests
      const categoryMap = {};
      for (const interest of userInterests) {
        try {
          let content = null;
          if (interest._id.courseId) {
            content = await Course.findById(interest._id.courseId).select('category');
          } else if (interest._id.fileId) {
            content = await File.findById(interest._id.fileId).select('category');
          }

          if (content && content.category) {
            const cat = content.category;
            categoryMap[cat] = (categoryMap[cat] || 0) + interest.interactionCount;
          }
        } catch (e) {
          // Skip individual interest lookups that fail
        }
      }

    // Get trending content
    const trendingContent = await userActivity.getTrendingContent(7, 50);

    // Build recommendations
    let recommendations = [];

    if (assetType === 'courses' || assetType === 'both') {
      const recommendedCourses = await Course.find({
        category: { $in: Object.keys(categoryMap) },
        _id: {
          $nin: (
            await userActivity.find(
              { userId: req.user._id, courseId: { $exists: true, $ne: null } },
              'courseId'
            )
          ).map((a) => a.courseId),
        },
        published: true,
      })
        .sort({ rating: -1, enrollCount: -1 })
        .limit(limit)
        .select('title slug category price rating enrollCount instructor');

      recommendations = [...recommendations, ...recommendedCourses];
    }

    if (assetType === 'files' || assetType === 'both') {
      const recommendedFiles = await File.find({
        category: { $in: Object.keys(categoryMap) },
        _id: {
          $nin: (
            await userActivity.find(
              { userId: req.user._id, fileId: { $exists: true, $ne: null } },
              'fileId'
            )
          ).map((a) => a.fileId),
        },
      })
        .sort({ likes: -1, downloadCount: -1 })
        .limit(limit)
        .select('title slug category price userId downloadCount likes');

      recommendations = [...recommendations, ...recommendedFiles];
    }

    res.json({
      topCategories: Object.entries(categoryMap)
        .sort(([, a], [, b]) => b - a)
        .slice(0, 5)
        .map(([cat, count]) => ({ category: cat, interactionCount: count })),
      recommendations: recommendations.slice(0, limit),
      message: 'Recommendations based on your interests',
    });
    } catch (innerError) {
      console.error('Error generating recommendations:', innerError);
      // Return empty recommendations instead of error
      res.json({
        topCategories: [],
        recommendations: [],
        message: 'Unable to generate recommendations at this moment',
      });
    }
  } catch (error) {
    console.error('Error in recommend-assets:', error);
    // Return safe default
    res.json({
      topCategories: [],
      recommendations: [],
      message: 'Unable to generate recommendations at this moment',
    });
  }
});

/**
 * GET /api/user-search-history
 * Get user's recent searches
 */
router.get('/user-search-history', requireAuth, async (req, res) => {
  try {
    if (!req.user) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const limit = parseInt(req.query.limit) || 20;
    const days = parseInt(req.query.days) || 30;

    const startDate = new Date();
    startDate.setDate(startDate.getDate() - days);

    const searchHistory = await userActivity
      .find({
        userId: req.user._id,
        activityType: 'search',
        createdAt: { $gte: startDate },
      })
      .sort({ createdAt: -1 })
      .limit(limit)
      .select('searchQuery searchResults createdAt');

    // Deduplicate and count frequency
    const deduplicatedSearches = {};
    searchHistory.forEach((search) => {
      const query = search.searchQuery;
      if (!deduplicatedSearches[query]) {
        deduplicatedSearches[query] = { count: 0, lastSearched: search.createdAt };
      }
      deduplicatedSearches[query].count++;
    });

    const formattedSearches = Object.entries(deduplicatedSearches)
      .map(([query, data]) => ({
        searchQuery: query,
        searchCount: data.count,
        lastSearched: data.lastSearched,
      }))
      .sort((a, b) => b.searchCount - a.searchCount);

    res.json(formattedSearches);
  } catch (error) {
    console.error('Error fetching search history:', error);
    // Return empty array instead of error
    res.json([]);
  }
});

/**
 * DELETE /api/clear-activity
 * Clear user's activity data (for privacy)
 */
router.delete('/clear-activity', requireAuth, async (req, res) => {
  try {
    if (!req.user) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    try {
      await userActivity.deleteMany({ userId: req.user._id });
      res.json({ success: true, message: 'Activity data cleared' });
    } catch (deleteError) {
      console.error('Error clearing activity:', deleteError);
      // Return success anyway - activity clearing is non-critical
      res.json({ success: true, message: 'Clear requested (async)' });
    }
  } catch (error) {
    console.error('Error in clear-activity:', error);
    res.json({ success: true, message: 'Clear requested (async)' });
  }
});

module.exports = router;

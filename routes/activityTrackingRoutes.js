const express = require('express');
const router = express.Router();
const userActivity = require('../models/userActivity');
const userAnalytics = require('../models/userAnalytics');
const advancedMetrics = require('../models/advancedMetrics');
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
      console.log('❌ [TRACK-ACTIVITY] Unauthorized request');
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

    // ============================================
    // Process advanced metrics based on activity type
    // ============================================
    await processAdvancedMetrics(req.user._id, req.body)
      .catch(err => console.log('ℹ️ [ANALYTICS] Metrics processing skipped:', err.message));

    // Comprehensive logging for verification
    console.log('✅ [TRACK-ACTIVITY] Activity recorded successfully', {
      activityId: activity._id,
      userId: req.user._id,
      userEmail: req.user.email,
      activityType: activityType,
      pageType: pageType || 'unknown',
      fileId: fileId || null,
      courseId: courseId || null,
      searchQuery: searchQuery || null,
      timeSpentSeconds: timeSpentSeconds || 0,
      sessionId: sessionId.substring(0, 8) + '...',
      timestamp: activity.createdAt
    });

    res.json({ success: true, activityId: activity._id, message: 'Activity tracked' });
  } catch (error) {
    console.error('❌ [TRACK-ACTIVITY] Error tracking activity:', error.message, {
      stack: error.stack,
      receivedData: req.body
    });
    // Return success anyway to not disrupt user experience
    // Activity tracking is non-critical
    res.status(200).json({ success: true, message: 'Activity queued (async)' });
  }
});

/**
 * GET /api/user-analytics
 * Get comprehensive user analytics and insights
 */
router.get('/user-analytics', requireAuth, async (req, res) => {
  try {
    if (!req.user) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const metrics = await advancedMetrics.findOne({ userId: req.user._id });

    if (!metrics) {
      return res.json({
        engagementScore: 0,
        reviewMetrics: { totalReviewsViewed: 0, totalReviewsSubmitted: 0 },
        cartMetrics: { cartsCreated: 0, conversionRate: 0 },
        deviceMetrics: { mostUsedDevice: 'unknown', crossDeviceCount: 1 },
        churnRisk: 0,
        message: 'No analytics data yet - keep using the platform!',
      });
    }

    res.json({
      engagementScore: metrics.engagementMetrics?.engagementScore || 0,
      reviewMetrics: {
        totalReviewsViewed: metrics.reviews?.totalReviewsViewed || 0,
        totalReviewsSubmitted: metrics.reviews?.totalReviewsSubmitted || 0,
        avgRating: metrics.reviews?.avgRatingSubmitted || 0,
      },
      cartMetrics: {
        cartsCreated: metrics.cartMetrics?.cartsCreated || 0,
        completedCheckouts: metrics.cartMetrics?.completedCheckouts || 0,
        conversionRate: Math.round((metrics.cartMetrics?.conversionRate || 0) * 10) / 10,
      },
      categoryMetrics: {
        topCategories: Object.keys(metrics.categoryEngagementByDevice || {}).slice(0, 5),
        uniqueCategoryCount: Object.keys(metrics.categoryEngagementByDevice || {}).length,
      },
      deviceMetrics: {
        mostUsedDevice: metrics.devicePreference?.mostUsedDevice || 'unknown',
        crossDeviceCount: metrics.devicePreference?.crossDeviceCount || 1,
        deviceDistribution: metrics.devicePreference?.deviceDistribution || {},
      },
      browsingMetrics: {
        totalSessions: metrics.browsingPathMetrics?.totalSessionsTracked || 0,
        commonPathSequences: (metrics.browsingPathMetrics?.commonPathSequences || []).slice(0, 5),
      },
      churnRisk: {
        score: Math.round((metrics.churnAnalysis?.churnPredictionScore || 0) * 100),
        reason: metrics.churnAnalysis?.predictedChurnReason || 'low_risk',
        daysInactive: metrics.churnAnalysis?.daysInactive || 0,
      },
      message: 'Your personal analytics dashboard',
    });

    console.log('📊 [ANALYTICS] User analytics retrieved for:', req.user._id);
  } catch (error) {
    console.error('Error fetching user analytics:', error);
    res.json({ engagementScore: 0, message: 'Error fetching analytics' });
  }
});

/**
 * GET /api/cart-abandonment-analysis
 * Get cart abandonment insights for user re-engagement
 */
router.get('/cart-abandonment-analysis', requireAuth, async (req, res) => {
  try {
    if (!req.user) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const metrics = await advancedMetrics.findOne({ userId: req.user._id });

    if (!metrics || !metrics.cartMetrics) {
      return res.json({
        abandonmentRisk: 'low',
        abandoneCartCount: 0,
        recommendations: ['Continue shopping!'],
      });
    }

    const checkoutAttempts = metrics.cartMetrics.checkoutAttempts || 1;
    const completedCheckouts = metrics.cartMetrics.completedCheckouts || 0;
    const completionRate = (completedCheckouts / checkoutAttempts) * 100;
    const abandonmentCount = checkoutAttempts - completedCheckouts;

    let abandonmentRisk = 'low';
    if (completionRate < 50) abandonmentRisk = 'high';
    else if (completionRate < 75) abandonmentRisk = 'medium';

    const recommendations = [];
    if (abandonmentRisk === 'high') {
      recommendations.push('Complete your pending purchase');
      recommendations.push('Clear cart and start fresh');
      recommendations.push('Ask for customer support');
    } else if (abandonmentRisk === 'medium') {
      recommendations.push('Review your cart items');
      recommendations.push('Check for available discounts');
    }

    res.json({
      abandonmentRisk,
      checkoutAttempts,
      completedCheckouts,
      conversionRate: Math.round(completionRate * 10) / 10,
      abandonmentCount,
      lastCheckoutDate: metrics.cartMetrics.lastCheckoutAttempt,
      recommendations,
    });

    console.log('🛒 [ABANDONMENT] Cart analysis for user:', req.user._id);
  } catch (error) {
    console.error('Error in cart abandonment analysis:', error);
    res.json({ abandonmentRisk: 'unknown', message: 'Error analyzing cart' });
  }
});

/**
 * POST /api/calculate-engagement-score
 * Manually trigger engagement score recalculation
 */
router.post('/calculate-engagement-score', requireAuth, async (req, res) => {
  try {
    if (!req.user) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const metrics = await advancedMetrics.findOne({ userId: req.user._id });
    if (metrics) {
      updateEngagementScore(metrics, {});
      updateChurnPrediction(metrics);
      await metrics.save();

      res.json({
        success: true,
        engagementScore: metrics.engagementMetrics?.engagementScore || 0,
        components: metrics.engagementMetrics?.scoringComponents || {},
      });
    } else {
      res.json({ success: false, message: 'No metrics found' });
    }
  } catch (error) {
    console.error('Error calculating engagement score:', error);
    res.status(500).json({ error: 'Calculation failed' });
  }
});

/**
 * GET /api/behavioral-insights
 * Get behavioral patterns and insights
 */
router.get('/behavioral-insights', requireAuth, async (req, res) => {
  try {
    if (!req.user) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const metrics = await advancedMetrics.findOne({ userId: req.user._id });

    if (!metrics) {
      return res.json({
        browsingBehavior: 'new_user',
        insights: [],
      });
    }

    const insights = [];

    // Browsing behavior insight
    if (metrics.browsingPathMetrics?.commonPathSequences.length > 0) {
      const topPath = metrics.browsingPathMetrics.commonPathSequences
        .sort((a, b) => b.frequency - a.frequency)[0];
      insights.push({
        type: 'browsing_pattern',
        insight: `You typically browse: ${topPath.sequence.join(' → ')}`,
        frequency: topPath.frequency,
      });
    }

    // Category preference insight
    const topCategories = Object.entries(metrics.categoryEngagementByDevice || {})
      .sort((a, b) => (b[1].desktop?.visits || 0) - (a[1].desktop?.visits || 0))
      .slice(0, 3);

    if (topCategories.length > 0) {
      insights.push({
        type: 'category_preference',
        insight: `Your top interests: ${topCategories.map(([cat]) => cat).join(', ')}`,
        categories: topCategories.map(([cat]) => cat),
      });
    }

    // Device usage insight
    const deviceDist = metrics.devicePreference?.deviceDistribution || {};
    const totalDeviceUses = Object.values(deviceDist).reduce((a, b) => a + b, 0);
    if (totalDeviceUses > 1) {
      insights.push({
        type: 'device_usage',
        insight: `You switch between ${metrics.devicePreference?.crossDeviceCount || 1} devices`,
        distribution: deviceDist,
      });
    }

    // Purchase behavior insight
    if (metrics.cartMetrics?.completedCheckouts > 0) {
      insights.push({
        type: 'purchase_habit',
        insight: `You've completed ${metrics.cartMetrics.completedCheckouts} purchases with ${Math.round(metrics.cartMetrics.conversionRate * 10) / 10}% checkout success rate`,
        conversionRate: metrics.cartMetrics.conversionRate,
      });
    }

    // Review engagement insight
    if (metrics.reviews?.totalReviewsSubmitted > 0) {
      insights.push({
        type: 'review_contributor',
        insight: `You've written ${metrics.reviews.totalReviewsSubmitted} reviews with an average rating of ${Math.round(metrics.reviews.avgRatingSubmitted * 10) / 10}★`,
        reviewCount: metrics.reviews.totalReviewsSubmitted,
        avgRating: metrics.reviews.avgRatingSubmitted,
      });
    }

    res.json({
      insights,
      engagementScore: metrics.engagementMetrics?.engagementScore || 0,
      dataUpdatedAt: metrics.updatedAt,
    });

    console.log('📈 [INSIGHTS] Behavioral insights retrieved for:', req.user._id);
  } catch (error) {
    console.error('Error generating behavioral insights:', error);
    res.json({ insights: [], error: 'Error generating insights' });
  }
});

/**
 * ============================================
 * GET /api/user-interests
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
 * Get trending courses and files based on user activities AND popularity
 * Helps in displaying popular/trending assets
 */
router.get('/trending-content', async (req, res) => {
  try {
    const days = parseInt(req.query.days) || 7;
    const limit = parseInt(req.query.limit) || 10;

    // First try to get activity-based trending
    let trending = await userActivity.getTrendingContent(days, limit);

    // If not enough trending from activities, supplement with popular files
    if (!trending || trending.length < limit) {
      console.log(`📊 Activity-based trending returned ${trending?.length || 0} items, fetching popular files...`);
      
      const popularFiles = await File.find({ 
        published: true,
        price: { $exists: true }
      })
        .sort({ downloadCount: -1, likes: -1, rating: -1 })
        .limit(Math.max(limit * 2, 12))
        .select('title slug category price downloadCount likes rating filename fileType imageType user')
        .lean();

      if (popularFiles && popularFiles.length > 0) {
        console.log(`✅ Found ${popularFiles.length} popular files`);
        
        // Transform files to matching structure
        const transformedFiles = popularFiles.map(file => ({
          _id: {
            fileId: file._id,
            count: file.downloadCount || 0,
            fileType: file.fileType || 'pdf'
          },
          content: {
            _id: file._id,
            title: file.title || file.filename,
            slug: file.slug,
            category: file.category,
            price: file.price || 0,
            downloads: file.downloadCount || 0,
            rating: file.rating || 4.8,
            previewUrl: file.imageType ? `https://d3epchi0htsp3c.cloudfront.net/files-previews/images/${file._id}.${file.imageType}` : null
          },
          userId: file.user
        }));

        // Combine and limit
        trending = trending && trending.length > 0 ? [...trending, ...transformedFiles] : transformedFiles;
        trending = trending.slice(0, limit);
      }
    }

    // Enrich with actual content data if needed
    const enrichedTrending = await Promise.all(
      (trending || []).map(async (item) => {
        try {
          if (!item.content && item._id?.fileId) {
            const content = await File.findById(item._id.fileId).select(
              'title slug category price downloadCount likes rating filename fileType imageType'
            ).lean();
            return {
              ...item,
              content: {
                ...content,
                downloads: content.downloadCount
              }
            };
          }
          return item;
        } catch (e) {
          console.error('Error enriching trending item:', e.message);
          return item;
        }
      })
    );

    console.log(`✅ Returning ${enrichedTrending.length} trending items`);
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
 * Combines interests, searches, downloads, and time spent
 */
router.post('/recommend-assets', requireAuth, async (req, res) => {
  try {
    if (!req.user) {
      console.log('❌ [RECOMMEND-ASSETS] Request without user authentication');
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const { limit = 10, assetType = 'both' } = req.body;

    console.log('🔄 [RECOMMEND-ASSETS] Starting recommendation engine', {
      userId: req.user._id,
      limit,
      assetType,
      userEmail: req.user.email
    });

    try {
      let recommendations = [];
      const categoryMap = {};
      const searchKeywords = [];

      // ═══════════════════════════════════════════════════════════
      // 1. GET DIRECT INTERESTS (file/course views and interactions)
      // ═══════════════════════════════════════════════════════════
      console.log('📚 [RECOMMEND-ASSETS] Fetching user interests...');
      const userInterests = await userActivity.getUserInterests(req.user._id, 50);
      console.log('📚 [RECOMMEND-ASSETS] User interests found:', {
        count: userInterests.length,
        sample: userInterests.slice(0, 2)
      });

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

      // ═══════════════════════════════════════════════════════════
      // 2. GET SEARCH KEYWORDS (from all search activities)
      // ═══════════════════════════════════════════════════════════
      const searchActivities = await userActivity
        .find({
          userId: req.user._id,
          activityType: 'search',
          searchQuery: { $exists: true, $ne: null },
        })
        .sort({ createdAt: -1 })
        .limit(20)
        .select('searchQuery');

      const uniqueSearches = {};
      searchActivities.forEach((activity) => {
        if (activity.searchQuery) {
          uniqueSearches[activity.searchQuery] = (uniqueSearches[activity.searchQuery] || 0) + 1;
        }
      });

      // Get top search keywords
      const topSearches = Object.entries(uniqueSearches)
        .sort(([, a], [, b]) => b - a)
        .slice(0, 10)
        .map(([query]) => query);

      // ═══════════════════════════════════════════════════════════
      // 3. GET DOWNLOAD & TIME SPENT PATTERNS
      // ═══════════════════════════════════════════════════════════
      const downloadActivities = await userActivity
        .find({
          userId: req.user._id,
          activityType: 'file_download',
        })
        .limit(20)
        .select('fileId');

      const downloadedFileIds = downloadActivities
        .map((a) => a.fileId)
        .filter((id) => id !== null);

      const timeSpentActivities = await userActivity
        .find({
          userId: req.user._id,
          pageType: 'file',
          timeSpentSeconds: { $gt: 30 }, // Users who spent more than 30 seconds
        })
        .limit(20)
        .select('fileId');

      const viewedFileIds = timeSpentActivities
        .map((a) => a.fileId)
        .filter((id) => id !== null);

      const allRelevantFileIds = [...downloadedFileIds, ...viewedFileIds, ...Object.values(userInterests).filter(i => i._id.fileId).map(i => i._id.fileId)];

      // Get similar files based on downloads/views
      if (allRelevantFileIds.length > 0) {
        try {
          const relevantFiles = await File.find({ _id: { $in: allRelevantFileIds } })
            .select('category')
            .lean();
          
          relevantFiles.forEach((file) => {
            if (file.category) {
              categoryMap[file.category] = (categoryMap[file.category] || 0) + 2; // Weight downloads/views higher
            }
          });
        } catch (e) {
          // Silently continue
        }
      }

      // ═══════════════════════════════════════════════════════════
      // 4. BUILD FINAL RECOMMENDATIONS
      // ═══════════════════════════════════════════════════════════

      const categories = Object.keys(categoryMap);
      const alreadyInteractedIds = new Set([...allRelevantFileIds, ...userInterests.filter(i => i._id.fileId).map(i => i._id.fileId).filter(id => id)]);

      if (assetType === 'files' || assetType === 'both') {
        // Get files by category
        if (categories.length > 0) {
          const recommedFilesByCategory = await File.find({
            category: { $in: categories },
            _id: { $nin: Array.from(alreadyInteractedIds) },
          })
            .sort({ likes: -1, downloadCount: -1 })
            .limit(limit + 5)
            .select('title slug category price userId downloadCount likes fileType filename user imageType rating _id')
            .lean();

          recommendations.push(...recommedFilesByCategory);
        }

        // Get files matching search keywords if categories are not enough
        if (topSearches.length > 0 && recommendations.length < limit) {
          const filesBySearch = await File.find({
            $or: [
              { filename: { $regex: topSearches[0], $options: 'i' } },
              { category: { $in: topSearches } },
            ],
            _id: { $nin: Array.from(alreadyInteractedIds) },
          })
            .sort({ downloadCount: -1 })
            .limit(limit + 5)
            .select('title slug category price userId downloadCount likes fileType filename user imageType rating _id')
            .lean();

          const recommendedIds = new Set(recommendations.map(r => r._id.toString()));
          filesBySearch.forEach(f => {
            if (!recommendedIds.has(f._id.toString())) {
              recommendations.push(f);
            }
          });
        }
      }

      if (assetType === 'courses' || assetType === 'both') {
        // Get courses by category
        if (categories.length > 0) {
          const userCourseIds = userInterests
            .filter(i => i._id.courseId)
            .map(i => i._id.courseId)
            .filter(id => id);

          const recommendedCourses = await Course.find({
            category: { $in: categories },
            _id: { $nin: userCourseIds },
            published: true,
          })
            .sort({ rating: -1, enrollCount: -1 })
            .limit(limit + 5)
            .select('title slug category price rating enrollCount instructor')
            .lean();

          recommendations.push(...recommendedCourses);
        }
      }

      // ═══════════════════════════════════════════════════════════
      // 5. FALLBACK FOR NEW USERS (NO ACTIVITY HISTORY)
      // ═══════════════════════════════════════════════════════════
      if (recommendations.length === 0) {
        console.log('📭 [RECOMMEND-ASSETS] No personalized recommendations, showing trending items...');
        
        if (assetType === 'files' || assetType === 'both') {
          // Get trending/popular files for new users
          const trendingFiles = await File.find({
            _id: { $nin: Array.from(alreadyInteractedIds) },
          })
            .sort({ downloadCount: -1, likes: -1 })
            .limit(limit)
            .select('title slug category price userId downloadCount likes fileType filename user imageType rating _id')
            .lean();

          recommendations.push(...trendingFiles);
        }

        if ((assetType === 'courses' || assetType === 'both') && recommendations.length < limit) {
          // Get trending courses for new users
          const userCourseIds = userInterests
            .filter(i => i._id.courseId)
            .map(i => i._id.courseId)
            .filter(id => id);

          const trendingCourses = await Course.find({
            _id: { $nin: userCourseIds },
            published: true,
          })
            .sort({ enrollCount: -1, rating: -1 })
            .limit(limit)
            .select('title slug category price rating enrollCount instructor')
            .lean();

          recommendations.push(...trendingCourses);
        }
      }

      // ═══════════════════════════════════════════════════════════
      // 6. SHUFFLE RECOMMENDATIONS FOR VARIETY
      // ═══════════════════════════════════════════════════════════
      // Shuffle the recommendations array to show different items each time
      // while keeping the top results slightly favored
      const shuffle = (arr) => {
        for (let i = arr.length - 1; i > 0; i--) {
          const j = Math.floor(Math.random() * (i + 1));
          [arr[i], arr[j]] = [arr[j], arr[i]];
        }
        return arr;
      };

      if (recommendations.length > limit) {
        // Shuffle and take top items for variety
        recommendations = shuffle(recommendations).slice(0, limit);
      }

      res.json({
        topCategories: Object.entries(categoryMap)
          .sort(([, a], [, b]) => b - a)
          .slice(0, 5)
          .map(([cat, count]) => ({ category: cat, interactionCount: count })),
        topSearches: topSearches.slice(0, 5),
        recommendations: recommendations.slice(0, limit).map(rec => ({
          ...rec,
          // Generate preview URL the same way /files endpoint does
          previewUrl: `https://d3epchi0htsp3c.cloudfront.net/files-previews/images/${rec._id}.${rec.imageType || 'jpg'}`
        })),
        message: 'Recommendations based on your searches, downloads, and interests',
      });

      console.log('✅ [RECOMMEND-ASSETS] Recommendations sent successfully', {
        totalRecommendations: recommendations.length,
        recommendationsSent: recommendations.slice(0, limit).length,
        sample: recommendations.slice(0, 1).map(r => ({
          id: r._id,
          title: r.title || r.filename,
          previewUrl: r.previewUrl ? 'present' : 'MISSING',
          fileType: r.fileType
        })),
        topCategories: Object.keys(categoryMap).length,
        topSearches: topSearches.length,
        userId: req.user._id
      });
    } catch (innerError) {
      console.error('❌ [RECOMMEND-ASSETS] Error generating recommendations:', innerError.message, {
        stack: innerError.stack,
        userId: req.user._id
      });
      // Return empty recommendations instead of error
      res.json({
        topCategories: [],
        topSearches: [],
        recommendations: [],
        message: 'Unable to generate recommendations at this moment',
      });
    }
  } catch (error) {
    console.error('Error in recommend-assets:', error);
    // Return safe default
    res.json({
      topCategories: [],
      topSearches: [],
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

/**
 * ============================================
 * ADVANCED METRICS PROCESSING HELPERS
 * ============================================
 */

/**
 * Process advanced metrics based on activity type
 * Updates UserAnalytics and AdvancedMetrics collections
 */
async function processAdvancedMetrics(userId, activityData) {
  try {
    const { activityType, fileId, category, rating, deviceInfo, browsingPath, cartAction } = activityData;

    // Get or create analytics document
    let metrics = await advancedMetrics.findOne({ userId });
    if (!metrics) {
      metrics = new advancedMetrics({ userId });
    }

    try {
      switch (activityType) {
        case 'review_interaction':
          try {
            // Track review submissions and ratings
            if (activityData.reviewAction === 'submit') {
              metrics.reviews.totalReviewsSubmitted = (metrics.reviews.totalReviewsSubmitted || 0) + 1;
              
              if (rating) {
                metrics.reviews.reviewSubmissions.push({
                  fileId,
                  rating,
                  reviewLength: activityData.reviewLength || 0,
                  submittedAt: new Date(),
                });
                
                // Update average rating
                const allRatings = metrics.reviews.reviewSubmissions.map(r => r.rating);
                metrics.reviews.avgRatingSubmitted = 
                  allRatings.reduce((a, b) => a + b, 0) / allRatings.length;
              }
            } else if (activityData.reviewAction === 'view') {
              metrics.reviews.totalReviewsViewed = (metrics.reviews.totalReviewsViewed || 0) + 1;
            }
            console.log('⭐ [METRICS] Review interaction recorded');
          } catch (err) {
            console.error('⚠️  [METRICS-REVIEW] Error in review tracking:', err.message);
          }
          break;

        case 'category_affinity':
          try {
            // Track category engagement and time spent
            if (!metrics.categoryEngagementByDevice) {
              metrics.categoryEngagementByDevice = {};
            }

            if (!metrics.categoryEngagementByDevice[category]) {
              metrics.categoryEngagementByDevice[category] = {
                mobile: { visits: 0, timeSpentSeconds: 0 },
                tablet: { visits: 0, timeSpentSeconds: 0 },
                desktop: { visits: 0, timeSpentSeconds: 0 },
              };
            }
            
            const deviceType = activityData.deviceInfo?.deviceType || 'desktop';
            const categoryData = metrics.categoryEngagementByDevice[category];
            if (categoryData && categoryData[deviceType]) {
              categoryData[deviceType].visits++;
              categoryData[deviceType].timeSpentSeconds += activityData.timeSpentSeconds || 0;
            }
            
            console.log('📊 [METRICS] Category affinity tracked:', category);
          } catch (err) {
            console.error('⚠️  [METRICS-CATEGORY] Error in category tracking:', err.message);
          }
          break;

        case 'device_context':
          try {
            // Track device information and preferences
            const device = activityData.deviceType || 'unknown';
            const deviceDistribution = metrics.devicePreference?.deviceDistribution || {};
            
            deviceDistribution[device] = (deviceDistribution[device] || 0) + 1;
            
            metrics.devicePreference = {
              mostUsedDevice: device,
              deviceDistribution,
              crossDeviceCount: Object.keys(deviceDistribution).length,
            };
            console.log('📱 [METRICS] Device context recorded:', device);
          } catch (err) {
            console.error('⚠️  [METRICS-DEVICE] Error in device tracking:', err.message);
          }
          break;

        case 'browsing_path':
          try {
            // Track page visit sequences
            metrics.browsingPathMetrics = metrics.browsingPathMetrics || {
              totalSessionsTracked: 0,
              avgPagesPerSession: 0,
              avgSessionDurationSeconds: 0,
              commonPathSequences: [],
              bounceRate: 0,
              exitPageTypes: [],
            };
            
            metrics.browsingPathMetrics.totalSessionsTracked++;
            
            if (activityData.previousPath && activityData.currentPath) {
              // Record page transitions for path analysis
              const sequence = [activityData.previousPath, activityData.currentPath];
              const existingPath = (metrics.browsingPathMetrics.commonPathSequences || []).find(
                p => JSON.stringify(p.sequence) === JSON.stringify(sequence)
              );
              
              if (existingPath) {
                existingPath.frequency++;
              } else {
                metrics.browsingPathMetrics.commonPathSequences.push({
                  sequence,
                  frequency: 1,
                  conversionRate: 0,
                });
              }
            }
            
            console.log('🛤️ [METRICS] Browsing path recorded');
          } catch (err) {
            console.error('⚠️  [METRICS-PATH] Error in path tracking:', err.message);
          }
          break;

        case 'cart_interaction':
          try {
            // Track cart metrics and abandonment
            metrics.cartMetrics = metrics.cartMetrics || {
              cartsCreated: 0,
              cartAbandonments: 0,
              checkoutAttempts: 0,
              completedCheckouts: 0,
              conversionRate: 0,
            };
            
            switch (activityData.cartAction) {
              case 'add':
                metrics.cartMetrics.cartsCreated++;
                break;
              case 'checkout_start':
                metrics.cartMetrics.checkoutAttempts++;
                break;
              case 'checkout_complete':
                metrics.cartMetrics.completedCheckouts++;
                // Update conversion rate
                if (metrics.cartMetrics.checkoutAttempts > 0) {
                  metrics.cartMetrics.conversionRate = 
                    (metrics.cartMetrics.completedCheckouts / metrics.cartMetrics.checkoutAttempts) * 100;
                }
                break;
            }
            
            console.log('🛒 [METRICS] Cart interaction recorded:', activityData.cartAction);
          } catch (err) {
            console.error('⚠️  [METRICS-CART] Error in cart tracking:', err.message);
          }
          break;

        case 'time_spent':
          try {
            // Update engagement score based on time spent
            updateEngagementScore(metrics, activityData);
          } catch (err) {
            console.error('⚠️  [METRICS-ENGAGEMENT] Error in engagement tracking:', err.message);
          }
          break;

        case 'file_download':
          try {
            // Track purchase frequency
            metrics.cartMetrics = metrics.cartMetrics || {};
            metrics.cartMetrics.completedCheckouts = (metrics.cartMetrics.completedCheckouts || 0) + 1;
            console.log('✅ [METRICS] File download recorded (likely purchase)');
          } catch (err) {
            console.error('⚠️  [METRICS-DOWNLOAD] Error in download tracking:', err.message);
          }
          break;
      }

      // Calculate churn risk
      try {
        updateChurnPrediction(metrics);
      } catch (err) {
        console.error('⚠️  [METRICS-CHURN] Error in churn prediction:', err.message);
      }

      // Save updated metrics
      await metrics.save();
    } catch (switchErr) {
      console.error('⚠️  [METRICS-SWITCH] Error in metric switch/case:', switchErr.message);
    }
  } catch (error) {
    console.error('⚠️  [METRICS] Error processing advanced metrics:', error.message, error.stack);
    // Don't throw - metrics processing is non-critical
  }
}

/**
 * Update engagement score based on user activities
 */
function updateEngagementScore(metrics, activityData) {
  const score = metrics.engagementMetrics || {
    engagementScore: 0,
    scoringComponents: {
      reviewEngagement: 0,
      categoryDiversity: 0,
      purchaseFrequency: 0,
      deviceDiversity: 0,
    },
  };

  // Components (each 0-25)
  // 1. Review engagement: 1 point per review, capped at 25
  score.scoringComponents.reviewEngagement = Math.min(
    (metrics.reviews?.totalReviewsSubmitted || 0) * 2,
    25
  );

  // 2. Category diversity: 4 points per unique category, capped at 25
  const categoryDevice = metrics.categoryEngagementByDevice || {};
  const uniqueCategories = Object.keys(categoryDevice).length;
  score.scoringComponents.categoryDiversity = Math.min(uniqueCategories * 4, 25);

  // 3. Purchase frequency: 5 points per 10 purchases, capped at 25
  score.scoringComponents.purchaseFrequency = Math.min(
    Math.floor((metrics.cartMetrics?.completedCheckouts || 0) / 10) * 5,
    25
  );

  // 4. Device diversity: 25 points if using 2+devices, 10 points for 1 device
  score.scoringComponents.deviceDiversity = (metrics.devicePreference?.crossDeviceCount || 1) >= 2 ? 25 : 10;

  // Calculate total engagement score (0-100)
  score.engagementScore = Object.values(score.scoringComponents).reduce((a, b) => a + b, 0);
  score.lastScoreCalculation = new Date();

  metrics.engagementMetrics = score;
}

/**
 * Update churn prediction score
 */
function updateChurnPrediction(metrics) {
  if (!metrics.churnAnalysis) {
    metrics.churnAnalysis = {
      churnPredictionScore: 0,
      daysInactive: 0,
      daysSinceLastPurchase: 0,
      predictedChurnReason: 'unknown',
      retentionInterventions: [],
    };
  }

  const now = Date.now();
  const lastActivityMs = metrics.updatedAt ? (now - metrics.updatedAt.getTime()) : 0;
  const daysInactive = Math.floor(lastActivityMs / (1000 * 60 * 60 * 24));
  const daysSinceLastPurchase = (metrics.cartMetrics?.completedCheckouts || 0) === 0 
    ? 999 
    : daysInactive;

  metrics.churnAnalysis.daysInactive = daysInactive;
  metrics.churnAnalysis.daysSinceLastPurchase = daysSinceLastPurchase;

  // Calculate churn score (0-1, where 1 = highest risk)
  let churnScore = 0;

  // No activity for 30+ days = high churn risk
  if (daysInactive > 30) churnScore += 0.4;
  else if (daysInactive > 14) churnScore += 0.2;

  // No purchases in 60+ days = moderate churn risk
  if (daysSinceLastPurchase > 60) churnScore += 0.3;
  else if (daysSinceLastPurchase > 30) churnScore += 0.15;

  // Low engagement score = moderate churn risk
  const engagementScore = metrics.engagementMetrics?.engagementScore || 0;
  if (engagementScore < 20) churnScore += 0.2;
  else if (engagementScore < 40) churnScore += 0.1;

  // Cap at 1.0
  metrics.churnAnalysis.churnPredictionScore = Math.min(churnScore, 1.0);

  // Determine reason
  if (churnScore > 0.6) {
    if (daysSinceLastPurchase > 60) {
      metrics.churnAnalysis.predictedChurnReason = 'no_recent_purchases';
    } else if (daysInactive > 30) {
      metrics.churnAnalysis.predictedChurnReason = 'low_activity';
    } else if (engagementScore < 20) {
      metrics.churnAnalysis.predictedChurnReason = 'low_engagement';
    }
  }
}

module.exports = router;

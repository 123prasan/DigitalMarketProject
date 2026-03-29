const express = require('express');
const router = express.Router();
const Wishlist = require('../models/Wishlist');
const File = require('../models/file');
const authenticateJWT_user  = require('./authentication/jwtAuth.js');

// CloudFront domain for preview images
const CLOUDFRONT_DOMAIN = 'd3epchi0htsp3c.cloudfront.net';
const PREVIEW_BASE_URL = `https://${CLOUDFRONT_DOMAIN}/files-previews/images`;

/**
 * Build preview URL from file ID and imageType
 */
function buildPreviewUrl(fileId, imageType = 'jpg') {
  let ext = imageType || 'jpg';
  if (ext === 'jpeg') ext = 'jpg'; // normalization
  return `${PREVIEW_BASE_URL}/${fileId}.${ext}`;
}

/**
 * GET /api/wishlist
 * Get user's complete wishlist
 */
router.get('/', authenticateJWT_user, async (req, res) => {
  try {
    // Extract user ID - check multiple possible locations
    const userId = req.user?._id || req.user?.id || req.userId;

    if (!userId) {
      console.warn('⚠️ [Wishlist] No user ID found in request');
      return res.status(401).json({ error: 'Unauthorized - Please login' });
    }

    let wishlist = await Wishlist.getWishlist(userId);

    // Enrich wishlist items with proper CloudFront preview URLs
    if (wishlist && wishlist.items && wishlist.items.length > 0) {
      const enrichedItems = await Promise.all(
        wishlist.items.map(async (item) => {
          // Get imageType from the actual file and build CloudFront URL
          try {
            const file = await File.findById(item.fileId).select('imageType').lean();
            if (file && file.imageType) {
              // Use CloudFront URL with correct imageType
              item.fileDetails.previewUrl = buildPreviewUrl(item.fileId, file.imageType);
            } else {
              // Fallback to default jpg
              item.fileDetails.previewUrl = buildPreviewUrl(item.fileId, 'jpg');
            }
          } catch (err) {
            console.warn(`⚠️ [Wishlist] Could not get imageType for ${item.fileId}:`, err.message);
            item.fileDetails.previewUrl = buildPreviewUrl(item.fileId, 'jpg');
          }
          return item;
        })
      );
      wishlist.items = enrichedItems;
    }

    console.log(`✅ [Wishlist] Fetched wishlist for user ${String(userId).substring(0, 8)}...`, {
      totalItems: wishlist.totalItems,
      totalValue: wishlist.totalValue,
    });

    return res.json(wishlist);
  } catch (error) {
    console.error('❌ Error fetching wishlist:', error);
    res.status(500).json({ error: 'Failed to fetch wishlist' });
  }
});

/**
 * GET /api/wishlist/stats
 * Get wishlist statistics and analytics
 */
router.get('/stats', authenticateJWT_user, async (req, res) => {
  try {
    const userId = req.user?._id || req.user?.id || req.userId;

    if (!userId) {
      return res.status(401).json({ error: 'Unauthorized - Please login' });
    }

    const stats = await Wishlist.getStats(userId);

    console.log(`✅ [Wishlist] Fetched stats for user ${String(userId).substring(0, 8)}...`, stats);

    return res.json(stats);
  } catch (error) {
    console.error('❌ Error fetching wishlist stats:', error);
    res.status(500).json({ error: 'Failed to fetch wishlist stats' });
  }
});

/**
 * POST /api/wishlist/add/:fileId
 * Add item to wishlist
 */
router.post('/add/:fileId', authenticateJWT_user, async (req, res) => {
  try {
    const userId = req.user?._id || req.user?.id || req.userId;
    const { fileId } = req.params;

    if (!userId) {
      console.warn('⚠️ [Wishlist] No user authenticated for add request');
      return res.status(401).json({ error: 'Unauthorized - Please login' });
    }

    console.log(`🔍 [Wishlist] Adding file ${fileId} to user ${String(userId).substring(0, 8)}...`);

    // Fetch file details
    const file = await File.findById(fileId).select(
      'title filename slug category price rating downloadCount user fileType imageType previewUrl'
    );

    if (!file) {
      return res.status(404).json({ error: 'File not found' });
    }

    // Add to wishlist with proper preview URL
    const wishlist = await Wishlist.addItem(userId, fileId, {
      title: file.title || file.filename,
      filename: file.filename,
      slug: file.slug,
      category: file.category,
      price: file.price || 0,
      rating: file.rating,
      downloadCount: file.downloadCount || 0,
      user: file.user,
      fileType: file.fileType,
      imageType: file.imageType,
      previewUrl: buildPreviewUrl(fileId, file.imageType), // Use CloudFront URL
    });

    // Track activity
    try {
      await fetch(process.env.BASE_URL || 'http://localhost:3000', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          userId,
          activityType: 'wishlist_add',
          fileId,
          fileTitle: file.title || file.filename,
          category: file.category,
          price: file.price || 0,
        }),
      });
    } catch (err) {
      console.warn('Activity tracking failed for wishlist_add:', err.message);
    }

    console.log(
      `✅ [Wishlist] Added file ${String(fileId).substring(0, 8)}... to user ${String(userId).substring(0, 8)}...`
    );

    return res.json({
      message: 'Item added to wishlist',
      wishlist,
      totalItems: wishlist.totalItems,
    });
  } catch (error) {
    console.error('❌ Error adding to wishlist:', error);
    res.status(500).json({ error: 'Failed to add to wishlist' });
  }
});

/**
 * DELETE /api/wishlist/remove/:fileId
 * Remove item from wishlist
 */
router.delete('/remove/:fileId', authenticateJWT_user, async (req, res) => {
  try {
    const userId = req.user?._id || req.user?.id || req.userId;
    const { fileId } = req.params;

    if (!userId) {
      return res.status(401).json({ error: 'Unauthorized - Please login' });
    }

    const wishlist = await Wishlist.removeItem(userId, fileId);

    if (!wishlist) {
      return res.status(404).json({ error: 'Wishlist not found' });
    }

    // Track activity
    try {
      await fetch(process.env.BASE_URL || 'http://localhost:8000', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          userId,
          activityType: 'wishlist_remove',
          fileId,
        }),
      });
    } catch (err) {
      console.warn('Activity tracking failed for wishlist_remove:', err.message);
    }

    console.log(
      `✅ [Wishlist] Removed file ${String(fileId).substring(0, 8)}... from user ${String(userId).substring(0, 8)}...`
    );

    return res.json({
      message: 'Item removed from wishlist',
      wishlist,
      totalItems: wishlist.totalItems,
    });
  } catch (error) {
    console.error('❌ Error removing from wishlist:', error);
    res.status(500).json({ error: 'Failed to remove from wishlist' });
  }
});

/**
 * GET /api/wishlist/check/:fileId
 * Check if file is in user's wishlist
 */
router.get('/check/:fileId', authenticateJWT_user, async (req, res) => {
  try {
    const userId = req.user?._id || req.user?.id || req.userId;
    const { fileId } = req.params;

    if (!userId) {
      return res.status(401).json({ error: 'Unauthorized - Please login' });
    }

    const isInWishlist = await Wishlist.isInWishlist(userId, fileId);

    return res.json({ inWishlist: isInWishlist });
  } catch (error) {
    console.error('❌ Error checking wishlist:', error);
    res.status(500).json({ error: 'Failed to check wishlist' });
  }
});

/**
 * POST /api/wishlist/mark-purchased/:fileId
 * Mark item as purchased (move to completed)
 */
router.post('/mark-purchased/:fileId', authenticateJWT_user, async (req, res) => {
  try {
    const userId = req.user?._id || req.user?.id || req.userId;
    const { fileId } = req.params;

    if (!userId) {
      return res.status(401).json({ error: 'Unauthorized - Please login' });
    }

    const wishlist = await Wishlist.markAsPurchased(userId, fileId);

    if (!wishlist) {
      return res.status(404).json({ error: 'Wishlist not found' });
    }

    console.log(
      `✅ [Wishlist] Marked file ${String(fileId).substring(0, 8)}... as purchased for user ${String(userId).substring(0, 8)}...`
    );

    return res.json({
      message: 'Item marked as purchased',
      wishlist,
    });
  } catch (error) {
    console.error('❌ Error marking as purchased:', error);
    res.status(500).json({ error: 'Failed to mark as purchased' });
  }
});

/**
 * GET /api/wishlist/abandoned
 * Get abandoned wishlist items (admin/background job)
 */
router.get('/abandoned', async (req, res) => {
  try {
    // This could be protected with admin auth in production
    const abandonedWishlists = await Wishlist.getAbandonedItems(7); // 7 days threshold

    const abandonedItems = [];
    abandonedWishlists.forEach((wishlist) => {
      const cutoffDate = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
      wishlist.items.forEach((item) => {
        if (!item.purchased && item.dateAdded < cutoffDate && !item.reminderSent) {
          abandonedItems.push({
            userId: wishlist.userId,
            fileId: item.fileId,
            fileDetails: item.fileDetails,
            dateAdded: item.dateAdded,
            daysAbandoned: Math.floor((Date.now() - item.dateAdded) / (1000 * 60 * 60 * 24)),
          });
        }
      });
    });

    console.log(`📊 [Wishlist] Found ${abandonedItems.length} abandoned items`);

    return res.json({
      totalAbandoned: abandonedItems.length,
      items: abandonedItems,
    });
  } catch (error) {
    console.error('❌ Error fetching abandoned items:', error);
    res.status(500).json({ error: 'Failed to fetch abandoned items' });
  }
});

/**
 * POST /api/wishlist/count
 * Get wishlist count for user (lightweight endpoint)
 */
router.post('/count', authenticateJWT_user, async (req, res) => {
  try {
    const userId = req.user?._id || req.user?.id || req.userId;

    if (!userId) {
      return res.status(401).json({ error: 'Unauthorized - Please login', count: 0 });
    }

    const wishlist = await Wishlist.findOne({ userId });
    const count = wishlist ? wishlist.items.length : 0;

    return res.json({ count });
  } catch (error) {
    console.error('❌ Error getting wishlist count:', error);
    res.status(500).json({ error: 'Failed to get count', count: 0 });
  }
});

module.exports = router;

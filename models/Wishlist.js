const mongoose = require('mongoose');

/**
 * Wishlist/Favorites Schema
 * Tracks items users save for later purchase
 */
const wishlistSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      index: true,
    },
    
    items: [
      {
        fileId: {
          type: mongoose.Schema.Types.ObjectId,
          ref: 'File',
          required: true,
        },
        
        // Snapshot of file data at time of adding to wishlist
        fileDetails: {
          title: String,
          filename: String,
          slug: String,
          category: String,
          price: Number,
          rating: Number,
          downloadCount: Number,
          user: String, // Creator name
          fileType: String,
          imageType: String,
          previewUrl: String, // Image URL for preview
        },
        
        // Wishlist item metadata
        dateAdded: {
          type: Date,
          default: Date.now,
        },
        
        // Track if user was reminded about this item
        reminderSent: {
          type: Boolean,
          default: false,
        },
        
        reminderDate: Date,
        
        // Track if item was purchased
        purchased: {
          type: Boolean,
          default: false,
        },
        
        purchaseDate: Date,
      },
    ],
    
    // Metadata
    totalItems: {
      type: Number,
      default: 0,
    },
    
    totalValue: {
      type: Number,
      default: 0, // Sum of all items' prices
    },
    
    lastUpdated: {
      type: Date,
      default: Date.now,
    },
  },
  { timestamps: true }
);

// Index for faster queries
wishlistSchema.index({ userId: 1, 'items.fileId': 1 }, { unique: false });
wishlistSchema.index({ 'items.dateAdded': 1 }); // For abandoned items

// Middleware to update totals before saving - using async to avoid callback issues
wishlistSchema.pre('save', async function () {
  this.totalItems = this.items.length;
  this.totalValue = this.items.reduce((sum, item) => sum + (item.fileDetails?.price || 0), 0);
  this.lastUpdated = Date.now();
  // Return the promise implicitly - don't need next() callback
});

/**
 * Statics
 */

// Add item to wishlist
wishlistSchema.statics.addItem = async function (userId, fileId, fileDetails) {
  try {
    let wishlist = await this.findOne({ userId });

    if (!wishlist) {
      wishlist = new this({ userId, items: [] });
    }

    // Check if item already exists
    const exists = wishlist.items.some((item) => item.fileId.toString() === fileId.toString());
    if (!exists) {
      wishlist.items.push({
        fileId,
        fileDetails,
        dateAdded: new Date(),
      });
    }

    await wishlist.save();
    return wishlist;
  } catch (error) {
    console.error('Error adding item to wishlist:', error);
    throw error;
  }
};

// Remove item from wishlist
wishlistSchema.statics.removeItem = async function (userId, fileId) {
  try {
    const wishlist = await this.findOne({ userId });

    if (!wishlist) {
      return null;
    }

    wishlist.items = wishlist.items.filter((item) => item.fileId.toString() !== fileId.toString());
    await wishlist.save();
    return wishlist;
  } catch (error) {
    console.error('Error removing item from wishlist:', error);
    throw error;
  }
};

// Get user's wishlist
wishlistSchema.statics.getWishlist = async function (userId) {
  try {
    const wishlist = await this.findOne({ userId }).sort({ 'items.dateAdded': -1 });
    return wishlist || { userId, items: [], totalItems: 0, totalValue: 0 };
  } catch (error) {
    console.error('Error fetching wishlist:', error);
    throw error;
  }
};

// Check if item is in wishlist
wishlistSchema.statics.isInWishlist = async function (userId, fileId) {
  try {
    const wishlist = await this.findOne({ userId });
    if (!wishlist) return false;
    return wishlist.items.some((item) => item.fileId.toString() === fileId.toString());
  } catch (error) {
    console.error('Error checking wishlist:', error);
    return false;
  }
};

// Get abandoned wishlist items (not purchased after X days)
wishlistSchema.statics.getAbandonedItems = async function (daysThreshold = 7) {
  try {
    const cutoffDate = new Date(Date.now() - daysThreshold * 24 * 60 * 60 * 1000);

    const result = await this.find({
      'items.purchased': false,
      'items.dateAdded': { $lt: cutoffDate },
      'items.reminderSent': false,
    });

    return result;
  } catch (error) {
    console.error('Error fetching abandoned items:', error);
    throw error;
  }
};

// Mark reminder as sent
wishlistSchema.statics.markReminderSent = async function (userId, fileId) {
  try {
    const wishlist = await this.findOne({ userId });
    if (!wishlist) return null;

    const item = wishlist.items.find((item) => item.fileId.toString() === fileId.toString());
    if (item) {
      item.reminderSent = true;
      item.reminderDate = new Date();
    }

    await wishlist.save();
    return wishlist;
  } catch (error) {
    console.error('Error marking reminder as sent:', error);
    throw error;
  }
};

// Mark item as purchased
wishlistSchema.statics.markAsPurchased = async function (userId, fileId) {
  try {
    const wishlist = await this.findOne({ userId });
    if (!wishlist) return null;

    const item = wishlist.items.find((item) => item.fileId.toString() === fileId.toString());
    if (item) {
      item.purchased = true;
      item.purchaseDate = new Date();
    }

    await wishlist.save();
    return wishlist;
  } catch (error) {
    console.error('Error marking item as purchased:', error);
    throw error;
  }
};

// Get wishlist statistics
wishlistSchema.statics.getStats = async function (userId) {
  try {
    const wishlist = await this.findOne({ userId });
    if (!wishlist) {
      return {
        totalItems: 0,
        totalValue: 0,
        purchasedItems: 0,
        unpurchasedItems: 0,
        abandonedItems: 0,
      };
    }

    const purchasedItems = wishlist.items.filter((item) => item.purchased).length;
    const unpurchasedItems = wishlist.items.filter((item) => !item.purchased).length;
    const cutoffDate = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    const abandonedItems = wishlist.items.filter(
      (item) => !item.purchased && item.dateAdded < cutoffDate
    ).length;

    return {
      totalItems: wishlist.totalItems,
      totalValue: wishlist.totalValue,
      purchasedItems,
      unpurchasedItems,
      abandonedItems,
    };
  } catch (error) {
    console.error('Error fetching wishlist stats:', error);
    throw error;
  }
};

module.exports = mongoose.model('Wishlist', wishlistSchema);

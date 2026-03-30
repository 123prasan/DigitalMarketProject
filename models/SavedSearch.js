const mongoose = require('mongoose');

const savedSearchSchema = new mongoose.Schema(
    {
        userId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User',
            required: true,
            index: true
        },
        searchName: {
            type: String,
            required: true,
            trim: true,
            maxlength: 100
        },
        query: {
            type: String,
            required: true,
            trim: true
        },
        filters: {
            category: [String],
            priceMin: Number,
            priceMax: Number,
            minRating: Number,
            sortBy: String, // 'relevance', 'price-asc', 'price-desc', 'rating', 'newest', 'trending'
            assetType: String, // 'all', 'files', 'courses'
            creator: String,
            dateRange: String // 'week', 'month', '3months', '6months', 'year', 'all'
        },
        resultCount: Number,
        lastUsed: Date,
        createdAt: {
            type: Date,
            default: Date.now
        },
        updatedAt: {
            type: Date,
            default: Date.now
        }
    },
    { timestamps: true }
);

// Index for faster queries
savedSearchSchema.index({ userId: 1, createdAt: -1 });

module.exports = mongoose.model('SavedSearch', savedSearchSchema);

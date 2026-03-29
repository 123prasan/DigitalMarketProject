/**
 * Wishlist Manager - Frontend Library
 * Handles adding/removing items to/from wishlist
 */

class WishlistManager {
  constructor() {
    this.wishlistItems = new Set();
    this.isInitialized = false;
    this.userId = this.getUserId();
  }

  /**
   * Get user ID from DOM
   */
  getUserId() {
    const htmlUserId = document.documentElement.getAttribute('data-user-id');
    if (htmlUserId && htmlUserId.trim() !== '') return htmlUserId;

    const userElement = document.querySelector('[data-user-id]');
    if (userElement) {
      const userId = userElement.getAttribute('data-user-id');
      if (userId && userId.trim() !== '') return userId;
    }

    const storedUserId = localStorage.getItem('userId');
    if (storedUserId) return storedUserId;

    return null;
  }

  /**
   * Inject CSS for wishlist buttons to ensure they're always clickable
   */
  injectStyles() {
    const styleId = 'wishlist-styles';
    if (document.getElementById(styleId)) return; // Already injected

    const style = document.createElement('style');
    style.id = styleId;
    style.textContent = `
      /* Wishlist button styles - ensure it's always clickable */
      .v-card-wishlist-btn {
        pointer-events: auto !important;
        cursor: pointer !important;
        outline: none;
        background: white !important;
        border: 2px solid #f0f4f9 !important;
      }
      
      .v-card-wishlist-btn:hover {
        background: #fff8f0 !important;
        border-color: #ff6b6b !important;
        transform: scale(1.1);
        box-shadow: 0 4px 12px rgba(255, 107, 107, 0.3) !important;
      }
      
      .v-card-wishlist-btn:active {
        transform: scale(0.95);
      }
      
      .v-card-wishlist-btn.is-wishlisted {
        color: #ff6b6b !important;
        border-color: #ff6b6b !important;
      }
      
      .v-card-wishlist-btn.is-wishlisted i {
        font-weight: 900;
      }
      
      /* Ensure image doesn't interfere */
      .v-card-img {
        pointer-events: none;
      }
      
      /* Ensure card link doesn't capture button clicks */
      .v-card {
        position: relative;
      }
    `;
    document.head.appendChild(style);
    console.log('✨ [WishlistManager] Styles injected');
  }

  /**
   * Initialize wishlist manager
   */
  async init() {
    if (!this.userId) {
      console.warn('⚠️ [WishlistManager] No user ID found - wishlist disabled for guest users');
      return;
    }

    this.injectStyles(); // Inject CSS first
    await this.loadWishlist();
    this.attachEventListeners();
    this.isInitialized = true;

    console.log('✅ [WishlistManager] Initialized - User has', this.wishlistItems.size, 'items');
  }

  /**
   * Load user's wishlist from server
   */
  async loadWishlist() {
    try {
      console.log(`📦 [WishlistManager] Loading wishlist for user ${this.userId ? String(this.userId).substring(0, 8) + '...' : 'guest'}...`);

      const response = await fetch('/api/wishlist', {
        method: 'GET',
        headers: { 'Content-Type': 'application/json' },
      });

      if (!response.ok) {
        if (response.status === 401) {
          console.log('⚠️ [WishlistManager] User not authenticated (status 401)');
          return;
        }
        throw new Error(`HTTP ${response.status}`);
      }

      const data = await response.json();
      if (data.items && Array.isArray(data.items)) {
        this.wishlistItems = new Set(data.items.map((item) => item.fileId.toString()));
        console.log(`📦 [WishlistManager] Loaded ${this.wishlistItems.size} items from wishlist`);
      }

      // Update UI to reflect wishlist state
      this.updateAllHeartIcons();
      this.updateWishlistBadge();
    } catch (error) {
      console.error('❌ [WishlistManager] Failed to load wishlist:', error.message);
    }
  }

  /**
   * Add item to wishlist
   */
  async addToWishlist(fileId, fileTitle) {
    if (!this.userId) {
      console.error('❌ [WishlistManager] No user ID - cannot add to wishlist');
      this.showToast('Please login to add to wishlist', 'error');
      return false;
    }

    try {
      console.log(`💚 [WishlistManager] Adding ${fileTitle} to wishlist for user ${String(this.userId).substring(0, 8)}...`);

      const response = await fetch(`/api/wishlist/add/${fileId}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      });

      const data = await response.json();
      
      if (!response.ok) {
        console.error('❌ [WishlistManager] API Error:', data);
        throw new Error(data.error || `HTTP ${response.status}`);
      }

      this.wishlistItems.add(fileId.toString());
      this.updateAllHeartIcons();
      this.updateWishlistBadge();

      console.log(`💚 [WishlistManager] Added ${fileTitle} to wishlist`);
      this.showToast(`✨ Added to wishlist!`, 'success');

      // Animate the heart
      this.animateHeart(fileId);

      return true;
    } catch (error) {
      console.error('❌ [WishlistManager] Error adding to wishlist:', error.message);
      this.showToast('Failed to add to wishlist - ' + error.message, 'error');
      return false;
    }
  }

  /**
   * Remove item from wishlist
   */
  async removeFromWishlist(fileId, fileTitle) {
    try {
      console.log(`🤍 [WishlistManager] Removing ${fileTitle} from wishlist for user ${String(this.userId).substring(0, 8)}...`);

      const response = await fetch(`/api/wishlist/remove/${fileId}`, {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
      });

      const data = await response.json();

      if (!response.ok) {
        console.error('❌ [WishlistManager] API Error:', data);
        throw new Error(data.error || `HTTP ${response.status}`);
      }

      this.wishlistItems.delete(fileId.toString());
      this.updateAllHeartIcons();
      this.updateWishlistBadge();

      console.log(`🤍 [WishlistManager] Removed ${fileTitle} from wishlist`);
      this.showToast(`Removed from wishlist`, 'info');

      return true;
    } catch (error) {
      console.error('❌ [WishlistManager] Error removing from wishlist:', error.message);
      this.showToast('Failed to remove from wishlist - ' + error.message, 'error');
      return false;
    }
  }

  /**
   * Toggle wishlist status for an item
   */
  async toggleWishlist(fileId, fileTitle) {
    if (this.wishlistItems.has(fileId.toString())) {
      await this.removeFromWishlist(fileId, fileTitle);
    } else {
      await this.addToWishlist(fileId, fileTitle);
    }
  }

  /**
   * Check if item is in wishlist
   */
  isInWishlist(fileId) {
    return this.wishlistItems.has(fileId.toString());
  }

  /**
   * Update all heart icons on page based on wishlist state
   */
  updateAllHeartIcons() {
    document.querySelectorAll('[data-wishlist-btn]').forEach((btn) => {
      const fileId = btn.getAttribute('data-file-id');
      if (!fileId) return;

      const isInWishlist = this.isInWishlist(fileId);
      const icon = btn.querySelector('i');

      if (isInWishlist) {
        btn.classList.add('is-wishlisted');
        icon.classList.remove('fa-regular');
        icon.classList.add('fa-solid');
      } else {
        btn.classList.remove('is-wishlisted');
        icon.classList.remove('fa-solid');
        icon.classList.add('fa-regular');
      }
    });
  }

  /**
   * Update wishlist badge/count in navbar
   */
  updateWishlistBadge() {
    const badge = document.getElementById('vWishlistBadge');
    if (!badge) return;

    const count = this.wishlistItems.size;
    if (count > 0) {
      badge.textContent = count > 99 ? '99+' : count;
      badge.style.display = 'flex';
    } else {
      badge.style.display = 'none';
    }
  }

  /**
   * Animate heart icon
   */
  animateHeart(fileId) {
    const heartBtn = document.querySelector(`[data-wishlist-btn][data-file-id="${fileId}"]`);
    if (!heartBtn) return;

    heartBtn.style.animation = 'none';
    setTimeout(() => {
      heartBtn.style.animation = 'heartBounce 0.6s cubic-bezier(0.23, 1, 0.320, 1)';
    }, 10);

    setTimeout(() => {
      heartBtn.style.animation = '';
    }, 610);
  }

  /**
   * Attach event listeners to heart buttons
   */
  attachEventListeners() {
    console.log('📍 [WishlistManager] Attaching event listeners to document');
    
    document.addEventListener('click', (e) => {
      // Try to find the button - it could be the target or a parent
      let wishlistBtn = e.target.closest('[data-wishlist-btn]');
      
      if (!wishlistBtn) {
        wishlistBtn = e.target.closest('button[data-wishlist-btn]');
      }
      
      if (!wishlistBtn) {
        // Maybe click was on the icon inside the button
        wishlistBtn = e.target.closest('[data-wishlist-btn]');
      }
      
      if (!wishlistBtn) return; // Not a wishlist button

      console.log('🎯 [WishlistManager] Wishlist button clicked!');
      console.log('📦 [WishlistManager] Button element:', wishlistBtn);
      
      e.preventDefault();
      e.stopPropagation();

      const fileId = wishlistBtn.getAttribute('data-file-id');
      const fileTitle = wishlistBtn.getAttribute('data-file-title') || 'Item';

      console.log(`💚 [WishlistManager] Toggling wishlist for file ${fileId}: ${fileTitle}`);
      this.toggleWishlist(fileId, fileTitle);
    }, true); // Use capture phase for better event catching
  }

  /**
   * Show toast notification
   */
  showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `v-wishlist-toast ${type}`;

    let icon = 'fa-check-circle';
    if (type === 'error') icon = 'fa-exclamation-circle';
    if (type === 'info') icon = 'fa-info-circle';

    toast.innerHTML = `
      <i class="fa-solid ${icon}"></i>
      <span>${message}</span>
    `;

    const container = document.getElementById('vToastContainer') || document.body;
    container.appendChild(toast);

    // Animate in
    setTimeout(() => toast.classList.add('show'), 10);

    // Remove after 3 seconds
    setTimeout(() => {
      toast.classList.remove('show');
      setTimeout(() => toast.remove(), 300);
    }, 3000);
  }

  /**
   * Get wishlist count
   */
  getWishlistCount() {
    return this.wishlistItems.size;
  }

  /**
   * Get all wishlist items
   */
  getWishlistItems() {
    return Array.from(this.wishlistItems);
  }
}

// Global instance
window.WishlistManager_Instance = new WishlistManager();

// Initialize on DOM ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    window.WishlistManager_Instance.init();
  });
} else {
  window.WishlistManager_Instance.init();
}

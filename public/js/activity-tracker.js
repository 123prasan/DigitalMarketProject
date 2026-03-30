/**
 * Activity Tracker - Frontend Library
 * Tracks user activities: clicks, searches, page views, time spent
 * 
 * Usage:
 * 1. Include this script in your EJS templates: <script src="/js/activity-tracker.js"></script>
 * 2. Initialize: ActivityTracker.init({ autoTrack: true })
 * 3. Manual tracking: ActivityTracker.trackActivity({ activityType: 'click', ... })
 */

class ActivityTracker {
  constructor() {
    this.sessionId = this.getOrCreateSessionId();
    this.pageStartTime = Date.now();
    this.lastActivityTime = Date.now();
    this.scrollDepth = 0;
    this.isInitialized = false;
    this.userId = null;
  }

  /**
   * Initialize the activity tracker
   * @param {Object} options - Configuration options
   * @param {boolean} options.autoTrack - Enable automatic tracking
   * @param {number} options.batchInterval - Batch activity submissions (ms)
   * @param {Array} options.trackElements - CSS selectors to track clicks
   */
  init(options = {}) {
    const defaults = {
      autoTrack: true,
      batchInterval: 10000, // 10 seconds
      trackElements: [
        'a[href]',
        'button',
        '.download-btn',
        '.like-btn',
        '.review-btn',
        '.enroll-btn',
        '.add-to-cart',
        '.filter-btn',
      ],
    };

    this.options = { ...defaults, ...options };
    this.userId = this.getUserIdFromDOM();

    if (this.options.autoTrack) {
      this.setupAutoTracking();
    }

    this.isInitialized = true;
    
    // Initialize advanced tracking mechanisms
    this.initializeAdvancedTracking();
    

  }

  /**
   * Setup automatic tracking of user interactions
   */
  setupAutoTracking() {
    try {
      // Track page view
      this.trackPageView();

      // Track scroll depth
      this.setupScrollTracking();

      // Track clicks on important elements
      this.setupClickTracking();

      // Track searches
      this.setupSearchTracking();

      // Track time spent on page
      this.setupTimeSpentTracking();

      // Track before unload
      window.addEventListener('beforeunload', () => {
        this.trackTimeSpent();
      });

      // Batch activity submissions
      if (this.options.batchInterval > 0) {
        setInterval(() => {
          // Can be used to batch multiple activities
        }, this.options.batchInterval);
      }
    } catch (error) {
      // Don't throw - continue operation even if tracking fails
    }
  }

  /**
   * Get or create a session ID
   */
  getOrCreateSessionId() {
    let sessionId = localStorage.getItem('activitySessionId');
    if (!sessionId || this.isSessionExpired()) {
      sessionId = this.generateUuid();
      localStorage.setItem('activitySessionId', sessionId);
      localStorage.setItem('activitySessionStart', Date.now().toString());
    }
    return sessionId;
  }

  /**
   * Check if session has expired (24 hours)
   */
  isSessionExpired() {
    const sessionStart = localStorage.getItem('activitySessionStart');
    if (!sessionStart) return true;

    const hoursSinceStart = (Date.now() - parseInt(sessionStart)) / (1000 * 60 * 60);
    return hoursSinceStart > 24;
  }

  /**
   * Generate UUID
   */
  generateUuid() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
      const r = (Math.random() * 16) | 0,
        v = c === 'x' ? r : (r & 0x3) | 0x8;
      return v.toString(16);
    });
  }

  /**
   * Get user ID from DOM
   */
  getUserIdFromDOM() {
    // First try to get from html element data-user-id
    const htmlElement = document.documentElement;
    const htmlUserId = htmlElement.getAttribute('data-user-id');
    if (htmlUserId && htmlUserId.trim() !== '') {
      return htmlUserId;
    }
    
    // Then try any element with data-user-id
    const userElement = document.querySelector('[data-user-id]');
    if (userElement) {
      const userId = userElement.getAttribute('data-user-id');
      if (userId && userId.trim() !== '') {
        return userId;
      }
    }
    
    // Fall back to localStorage
    const storedUserId = localStorage.getItem('userId');
    if (storedUserId) {
      return storedUserId;
    }
    
    return null;
  }

  /**
   * Get page context information
   */
  getPageContext() {
    const path = window.location.pathname;
    let pageType = 'other';
    let courseId = null;
    let fileId = null;

    // First, check for data attributes on page (more reliable)
    const fileIdAttr = document.documentElement.getAttribute('data-file-id');
    const courseIdAttr = document.documentElement.getAttribute('data-course-id');
    
    if (fileIdAttr) {
      fileId = fileIdAttr;
      pageType = 'file';
    }
    if (courseIdAttr) {
      courseId = courseIdAttr;
      pageType = 'course';
    }

    // If not found in attributes, detect from URL
    if (!fileId && path.includes('/file/')) {
      pageType = 'file';
      // File URL format: /file/:slug/:id - capture the last segment (after last /)
      const fileMatch = path.match(/\/file\/[^\/]+\/([a-f0-9]+)$/i);
      fileId = fileMatch ? fileMatch[1] : null;
    }
    
    if (!courseId && path.includes('/course/')) {
      pageType = 'course';
      // Course URL format: /course/:id
      const courseMatch = path.match(/\/course\/([a-f0-9]+)/i);
      courseId = courseMatch ? courseMatch[1] : null;
    }
    
    if (path.includes('/search')) {
      pageType = 'search';
    }
    if (path.includes('/profile')) {
      pageType = 'profile';
    }
    if (path === '/' || path.includes('/dashboard')) {
      pageType = 'home';
    }
    if (path.includes('/category')) {
      pageType = 'category';
    }

    return {
      pageType,
      courseId,
      fileId,
      referrer: document.referrer,
    };
  }

  /**
   * Extract ID from URL using regex
   */
  extractIdFromUrl(regex) {
    const match = window.location.pathname.match(regex);
    return match ? match[1] : null;
  }

  /**
   * Track page view
   */
  trackPageView() {
    const context = this.getPageContext();
    this.trackActivity({
      activityType: 'page_view',
      ...context,
    });
  }

  /**
   * Setup scroll depth tracking
   */
  setupScrollTracking() {
    try {
      let maxScrollDepth = 0;

      window.addEventListener(
        'scroll',
        () => {
          try {
            const scrollDepth =
              ((window.scrollY + window.innerHeight) / document.documentElement.scrollHeight) * 100;
            maxScrollDepth = Math.max(maxScrollDepth, scrollDepth);
            this.scrollDepth = Math.min(100, Math.round(maxScrollDepth));
          } catch (e) {
            // Silently ignore scroll tracking errors
          }
        },
        { passive: true }
      );
    } catch (error) {
    }
  }

  /**
   * Setup click tracking
   */
  setupClickTracking() {
    try {
      document.addEventListener('click', (e) => {
        try {
          let target = e.target;

          // Traverse up to find tracked element
          while (target && target !== document) {
            if (
              this.options.trackElements.some(
                (selector) =>
                  target.matches && target.matches(selector)
              )
            ) {
              const elementId = target.id || target.className || target.tagName;
              const context = this.getPageContext();

              this.trackActivity({
                activityType: 'click',
                elementClicked: elementId,
                scrollDepth: this.scrollDepth,
                ...context,
              });
              break;
            }
            target = target.parentElement;
          }
        } catch (e) {
          // Silently ignore click tracking errors
        }
      });
    } catch (error) {
    }
  }

  /**
   * Setup search tracking
   */
  setupSearchTracking() {
    try {
      // Track search form submissions
      const searchForms = document.querySelectorAll('form[data-search], .search-form, [role="search"] form');

      searchForms.forEach((form) => {
        try {
          form.addEventListener('submit', (e) => {
            try {
              const formData = new FormData(form);
              const searchQuery = formData.get('q') || formData.get('search') || formData.get('query');

              if (searchQuery) {
                const context = this.getPageContext();
                this.trackActivity({
                  activityType: 'search',
                  searchQuery: searchQuery,
                  ...context,
                });
              }
            } catch (e) {
              // Silently ignore search tracking errors
            }
          });
        } catch (e) {
          // Silently ignore individual form setup errors
        }
      });

      // Track search input changes (for real-time search)
      const searchInputs = document.querySelectorAll('input[type="search"], input[name="q"], input[name="search"]');

      searchInputs.forEach((input) => {
        try {
          let searchTimeout;

          input.addEventListener('input', (e) => {
            try {
              clearTimeout(searchTimeout);
              searchTimeout = setTimeout(() => {
                if (e.target.value.trim().length > 2) {
                  const context = this.getPageContext();
                  this.trackActivity({
                    activityType: 'search',
                    searchQuery: e.target.value,
                    ...context,
                  });
                }
              }, 500); // Debounce for 500ms
            } catch (e) {
              // Silently ignore
            }
          });
        } catch (e) {
          // Silently ignore individual input setup errors
        }
      });
    } catch (error) {
    }
  }

  /**
   * Setup time spent tracking
   */
  setupTimeSpentTracking() {
    // Track time spent at regular intervals (every 5 seconds)
    setInterval(() => {
      this.updateLastActivityTime();
    }, 5000);

    // Track when user becomes active/inactive
    document.addEventListener('mousemove', () => {
      this.updateLastActivityTime();
    });

    document.addEventListener('keypress', () => {
      this.updateLastActivityTime();
    });

    document.addEventListener('click', () => {
      this.updateLastActivityTime();
    });
  }

  /**
   * Update last activity time
   */
  updateLastActivityTime() {
    this.lastActivityTime = Date.now();
  }

  /**
   * Track time spent on page
   */
  trackTimeSpent() {
    const timeSpentSeconds = Math.round((Date.now() - this.pageStartTime) / 1000);

    if (timeSpentSeconds > 5) {
      // Only track if user spent more than 5 seconds
      const context = this.getPageContext();
      this.trackActivity({
        activityType: 'time_spent',
        timeSpentSeconds,
        scrollDepth: this.scrollDepth,
        ...context,
      });
    }
  }

  /**
   * Main method to track any activity
   * @param {Object} activityData - Activity data to track
   */
  async trackActivity(activityData) {
    try {
      if (!this.isInitialized) {
        return; // Silently skip if not initialized
      }

      // Skip tracking if user is not authenticated
      if (!this.userId) {
        return; // Silently skip for guests
      }

      try {
        const payload = {
          ...activityData,
          sessionId: this.sessionId,
          userId: this.userId,
        };

        // Send activity to server without blocking
        fetch('/api/track-activity', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(payload),
        }).then(response => {
          return response.json();
        }).catch(err => {
          // Silently ignore network errors - don't disrupt user experience
        });
      } catch (error) {
        // Silently fail - don't disrupt user experience
      }
    } catch (error) {
      // Outer try-catch for any unexpected errors
    }
  }

  /**
   * Manually track a lesson start
   */
  trackLessonStart(lessonId, courseId) {
    this.trackActivity({
      activityType: 'lesson_start',
      lessonId,
      courseId,
      pageType: 'course',
    });
  }

  /**
   * Manually track a lesson completion
   */
  trackLessonComplete(lessonId, courseId) {
    this.trackActivity({
      activityType: 'lesson_complete',
      lessonId,
      courseId,
      pageType: 'course',
    });
  }

  /**
   * Manually track file download
   */
  trackFileDownload(fileId) {
    this.trackActivity({
      activityType: 'file_download',
      fileId,
      pageType: 'file',
    });
  }

  /**
   * Manually track file preview
   */
  trackFilePreview(fileId) {
    this.trackActivity({
      activityType: 'file_preview',
      fileId,
      pageType: 'file',
    });
  }

  /**
   * ============================================
   * ADVANCED TRACKING MECHANISMS
   * ============================================
   */

  /**
   * Track review/rating interaction
   * @param {string} fileId - File or course ID
   * @param {string} action - 'view', 'submit', 'helpful', 'report'
   * @param {number} rating - Star rating (1-5)
   * @param {string} reviewText - Review content (optional)
   */
  trackReviewInteraction(fileId, action = 'view', rating = null, reviewText = null) {
    const timestamp = Date.now();
    this.trackActivity({
      activityType: 'review_interaction',
      reviewAction: action,
      fileId,
      rating,
      reviewLength: reviewText ? reviewText.length : 0,
      pageType: 'file',
      timestamp,
    });

    // Also track segment
    localStorage.setItem(`review_${fileId}`, JSON.stringify({
      lastAction: action,
      lastRating: rating,
      timestamp,
    }));
  }

  /**
   * Track category affinity - time spent in each category
   * @param {string} category - Category name/ID
   * @param {number} timeSpentSeconds - Time spent in category
   */
  trackCategoryAffinity(category, timeSpentSeconds) {
    // Get existing category affinity from localStorage
    const affinityData = JSON.parse(localStorage.getItem('categoryAffinity') || '{}');
    
    if (!affinityData[category]) {
      affinityData[category] = { visits: 0, totalTime: 0 };
    }
    
    affinityData[category].visits++;
    affinityData[category].totalTime += timeSpentSeconds;
    affinityData[category].lastVisit = Date.now();
    
    localStorage.setItem('categoryAffinity', JSON.stringify(affinityData));

    this.trackActivity({
      activityType: 'category_affinity',
      category,
      timeSpentSeconds,
      categoryData: affinityData[category],
      pageType: 'category',
    });
  }

  /**
   * Get device information and track device type
   * @returns {Object} Device information
   */
  getDeviceInfo() {
    const ua = navigator.userAgent;
    const isMobile = /android|webos|iphone|ipad|ipod|blackberry|iemobile|opera mini/i.test(ua.toLowerCase());
    const isTablet = /ipad|android(?!.*mobi)|windows phone/i.test(ua.toLowerCase());
    const deviceType = isMobile ? 'mobile' : isTablet ? 'tablet' : 'desktop';
    
    // Get browser info
    let browser = 'unknown';
    if (ua.indexOf('Firefox') > -1) browser = 'Firefox';
    else if (ua.indexOf('Chrome') > -1) browser = 'Chrome';
    else if (ua.indexOf('Safari') > -1) browser = 'Safari';
    else if (ua.indexOf('Opera') > -1 || ua.indexOf('OPR') > -1) browser = 'Opera';
    else if (ua.indexOf('Edge') > -1) browser = 'Edge';

    // Get OS info
    let os = 'unknown';
    if (ua.indexOf('Win') > -1) os = 'Windows';
    else if (ua.indexOf('Mac') > -1) os = 'MacOS';
    else if (ua.indexOf('Linux') > -1) os = 'Linux';
    else if (ua.indexOf('Android') > -1) os = 'Android';
    else if (ua.indexOf('iPhone') > -1 || ua.indexOf('iPad') > -1) os = 'iOS';

    const deviceInfo = {
      deviceType,
      browser,
      os,
      screenResolution: `${window.screen.width}x${window.screen.height}`,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      language: navigator.language,
      connectionSpeed: navigator.connection?.effectiveType || 'unknown',
    };

    // Store device info in session
    sessionStorage.setItem('deviceInfo', JSON.stringify(deviceInfo));
    return deviceInfo;
  }

  /**
   * Track device type and context
   */
  trackDeviceContext() {
    const deviceInfo = this.getDeviceInfo();
    
    this.trackActivity({
      activityType: 'device_context',
      ...deviceInfo,
      pageType: this.getPageContext().pageType,
    });
  }

  /**
   * Track browsing path - sequence of pages visited
   */
  trackBrowsingPath() {
    // Initialize or get browsing path from session storage
    let browsingPath = JSON.parse(sessionStorage.getItem('browsingPath') || '[]');
    
    const pageContext = this.getPageContext();
    const pathEntry = {
      timestamp: Date.now(),
      pageType: pageContext.pageType,
      fileId: pageContext.fileId,
      courseId: pageContext.courseId,
      referrer: document.referrer,
      url: window.location.pathname,
    };

    browsingPath.push(pathEntry);
    
    // Keep last 50 pages in path
    if (browsingPath.length > 50) {
      browsingPath = browsingPath.slice(-50);
    }

    sessionStorage.setItem('browsingPath', JSON.stringify(browsingPath));

    this.trackActivity({
      activityType: 'browsing_path',
      pathLength: browsingPath.length,
      currentPath: pathEntry.pageType,
      previousPath: browsingPath.length > 1 ? browsingPath[browsingPath.length - 2].pageType : null,
      ...pageContext,
    });
  }

  /**
   * Track cart-related activity for abandonment detection
   * @param {string} action - 'add', 'remove', 'view', 'checkout_start', 'checkout_complete'
   * @param {Object} itemData - Item information (fileId, price, etc.)
   */
  trackCartInteraction(action = 'view', itemData = {}) {
    const cartData = JSON.parse(localStorage.getItem('cartSession') || '{}');
    
    const interaction = {
      action,
      itemData,
      timestamp: Date.now(),
      sessionId: this.sessionId,
    };

    // Track cart abandonment risk
    if (action === 'checkout_start') {
      cartData.lastCheckoutStart = Date.now();
      cartData.checkoutAttempts = (cartData.checkoutAttempts || 0) + 1;
    }

    if (action === 'checkout_complete') {
      cartData.completed = true;
      cartData.completedAt = Date.now();
      delete cartData.lastCheckoutStart;
    }

    if (action === 'add') {
      if (!cartData.items) cartData.items = [];
      cartData.items.push(itemData);
    }

    if (action === 'remove') {
      if (cartData.items) {
        cartData.items = cartData.items.filter(item => item.fileId !== itemData.fileId);
      }
    }

    localStorage.setItem('cartSession', JSON.stringify(cartData));

    // Calculate abandonment risk
    const abandonmentRisk = {
      checkoutAttempts: cartData.checkoutAttempts || 0,
      itemsInCart: cartData.items ? cartData.items.length : 0,
      timeSinceCheckoutStart: cartData.lastCheckoutStart 
        ? Math.round((Date.now() - cartData.lastCheckoutStart) / 1000) 
        : 0,
      completed: cartData.completed || false,
    };

    this.trackActivity({
      activityType: 'cart_interaction',
      cartAction: action,
      ...abandonmentRisk,
      ...itemData,
      pageType: 'checkout',
    });
  }

  /**
   * Setup cart abandonment auto-tracking
   */
  setupCartAbandonmentTracking() {
    try {
      // Track add to cart
      document.addEventListener('click', (e) => {
        if (e.target.matches('.add-to-cart, [data-action="add-to-cart"]')) {
          const fileId = e.target.getAttribute('data-file-id') 
            || e.target.closest('[data-file-id]')?.getAttribute('data-file-id')
            || document.documentElement.getAttribute('data-file-id');
          
          const fileName = e.target.getAttribute('data-file-name') 
            || e.target.closest('[data-file-name]')?.getAttribute('data-file-name');
          
          const price = e.target.getAttribute('data-price') 
            || e.target.closest('[data-price]')?.getAttribute('data-price');

          this.trackCartInteraction('add', { fileId, fileName, price });
        }

        if (e.target.matches('.checkout-btn, [data-action="checkout"]')) {
          this.trackCartInteraction('checkout_start', {});
        }
      });

      // Detect checkout completion (purchase successful)
      if (window.location.pathname.includes('/checkout-success') 
          || window.location.pathname.includes('/payment-success')
          || document.querySelector('[data-event="purchase-complete"]')) {
        this.trackCartInteraction('checkout_complete', {});
      }
    } catch (error) {
    }
  }

  /**
   * Setup review interaction auto-tracking
   */
  setupReviewTracking() {
    try {
      // Track review submissions
      document.addEventListener('submit', (e) => {
        if (e.target.matches('[data-form="review-form"], .review-form, [class*="review"][class*="form"]')) {
          e.preventDefault(); // Let form submit, but track first
          
          const fileId = document.documentElement.getAttribute('data-file-id');
          const ratingInput = e.target.querySelector('[name="rating"], input[type="range"]');
          const reviewText = e.target.querySelector('[name="review"], textarea');
          
          const rating = ratingInput ? parseInt(ratingInput.value) : null;
          const text = reviewText ? reviewText.value : null;

          this.trackReviewInteraction(fileId, 'submit', rating, text);
          
          // Re-submit form
          setTimeout(() => e.target.submit(), 100);
        }
      });

      // Track review view/hover
      document.addEventListener('mouseover', (e) => {
        if (e.target.matches('[data-review-id], .review-item, [class*="review"]')) {
          const reviewId = e.target.getAttribute('data-review-id');
          if (reviewId && !e.target.hasAttribute('data-tracked-view')) {
            const rating = e.target.querySelector('[class*="rating"], [data-rating]')?.getAttribute('data-rating');
            this.trackReviewInteraction(reviewId, 'view', rating);
            e.target.setAttribute('data-tracked-view', 'true');
          }
        }
      });
    } catch (error) {
    }
  }

  /**
   * Initialize all advanced tracking
   */
  initializeAdvancedTracking() {
    try {
      // Initialize device tracking
      this.trackDeviceContext();

      // Initialize browsing path tracking
      this.trackBrowsingPath();

      // Setup cart abandonment detection
      this.setupCartAbandonmentTracking();

      // Setup review interaction tracking
      this.setupReviewTracking();

      // Track category affinity every 30 seconds
      setInterval(() => {
        const category = this.getPageContext().pageType;
        if (category) {
          this.trackCategoryAffinity(category, 30);
        }
      }, 30000);
    } catch (error) {
    }
  }

  /**
   * Get user interests
   */
  async getUserInterests(limit = 10) {
    try {
      const response = await fetch(`/api/user-interests?limit=${limit}`);
      if (response.ok) {
        return await response.json();
      }
    } catch (error) {
    }
    return [];
  }

  /**
   * Get trending content
   */
  async getTrendingContent(days = 7, limit = 10) {
    try {
      const response = await fetch(`/api/trending-content?days=${days}&limit=${limit}`);
      if (response.ok) {
        return await response.json();
      }
    } catch (error) {
    }
    return [];
  }

  /**
   * Get recommendations
   */
  async getRecommendations(limit = 10, assetType = 'both') {
    try {
      const response = await fetch('/api/recommend-assets', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ limit, assetType }),
      });

      if (response.ok) {
        const data = await response.json();
        return data;
      }
    } catch (error) {
    }
    return { recommendations: [], topCategories: [] };
  }

  /**
   * Get activity summary
   */
  async getActivitySummary(days = 30) {
    try {
      const response = await fetch(`/api/activity-summary?days=${days}`);
      if (response.ok) {
        return await response.json();
      }
    } catch (error) {
    }
    return [];
  }

  /**
   * Clear all activity data
   */
  async clearActivity() {
    try {
      const response = await fetch('/api/clear-activity', {
        method: 'DELETE',
      });
      if (response.ok) {
        return await response.json();
      }
    } catch (error) {
    }
    return { success: false };
  }
}

// Create global instance
const ActivityTracker_Instance = new ActivityTracker();

// Export for use
if (typeof module !== 'undefined' && module.exports) {
  module.exports = ActivityTracker_Instance;
}

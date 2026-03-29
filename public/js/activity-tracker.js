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
    if (this.userId) {
      console.log('✓ ActivityTracker initialized - User ID:', this.userId.substring(0, 8) + '...');
    } else {
      console.log('⚠ ActivityTracker initialized - No user ID (guest user)');
    }
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
      console.warn('ActivityTracker setup error (non-critical):', error);
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
    const userElement = document.querySelector('[data-user-id]');
    if (userElement) {
      return userElement.getAttribute('data-user-id');
    }
    return localStorage.getItem('userId') || null;
  }

  /**
   * Get page context information
   */
  getPageContext() {
    const path = window.location.pathname;
    let pageType = 'other';
    let courseId = null;
    let fileId = null;

    // Detect page type from URL
    if (path.includes('/course/')) {
      pageType = 'course';
      courseId = this.extractIdFromUrl(/\/course\/([a-f0-9]+)/);
    } else if (path.includes('/file/') || path.includes('/files/')) {
      pageType = 'file';
      fileId = this.extractIdFromUrl(/\/file(?:s)?\/([a-f0-9]+)/);
    } else if (path.includes('/search')) {
      pageType = 'search';
    } else if (path.includes('/profile')) {
      pageType = 'profile';
    } else if (path === '/' || path.includes('/dashboard')) {
      pageType = 'home';
    } else if (path.includes('/category')) {
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
      console.warn('Scroll tracking setup failed:', error);
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
      console.warn('Click tracking setup failed:', error);
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
      console.warn('Search tracking setup failed:', error);
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
        console.debug('Activity tracking skipped: User not authenticated');
        return; // Silently skip for guests
      }

      try {
        const payload = {
          ...activityData,
          sessionId: this.sessionId,
        };

        // Send activity to server without blocking
        fetch('/api/track-activity', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(payload),
        }).then(response => {
          if (response.ok) {
            console.debug('✓ Activity sent:', { type: activityData.activityType, userId: this.userId });
          }
        }).catch(err => {
          // Silently ignore network errors - don't disrupt user experience
          console.debug('Activity tracking network error (non-critical):', err.message);
        });
      } catch (error) {
        // Silently fail - don't disrupt user experience
        console.debug('Activity tracking error (non-critical):', error.message);
      }
    } catch (error) {
      // Outer try-catch for any unexpected errors
      console.debug('Unexpected activity tracking error:', error.message);
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
   * Get user interests
   */
  async getUserInterests(limit = 10) {
    try {
      const response = await fetch(`/api/user-interests?limit=${limit}`);
      if (response.ok) {
        return await response.json();
      }
    } catch (error) {
      console.debug('Error fetching user interests:', error.message);
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
      console.debug('Error fetching trending content:', error.message);
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
        return await response.json();
      }
    } catch (error) {
      console.debug('Error fetching recommendations:', error.message);
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
      console.debug('Error fetching activity summary:', error.message);
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
      console.debug('Error clearing activity:', error.message);
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

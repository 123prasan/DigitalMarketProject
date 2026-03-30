/**
 * Performance & SEO Optimization Middleware
 * Location: /services/performanceOptimizer.js
 */

const compression = require('compression');

/**
 * Compression Middleware Configuration
 * Gzip compress responses over 1KB
 */
const compressionMiddleware = () => {
  return compression({
    level: 6, // Compression level (0-11, 6 is default)
    threshold: 1000, // Only compress if response size > 1KB
    filter: (req, res) => {
      // Don't compress if no-compression header present
      if (req.headers['x-no-compression']) {
        return false;
      }
      // Compress dynamic responses
      return compression.filter(req, res);
    }
  });
};

/**
 * Cache Control Headers Middleware
 * Set appropriate cache headers based on content type
 */
const cacheControlMiddleware = (req, res, next) => {
  // Static assets - cache for 1 year
  if (req.path.match(/\.(jpg|jpeg|png|gif|css|js|woff|woff2|ttf|eot|svg)$/i)) {
    res.set('Cache-Control', 'public, max-age=31536000, immutable');
    return next();
  }

  // Course and file pages - cache for 1 hour (updated frequently)
  if (req.path.match(/\/(course|file)\//) || req.path.match(/\/(courses|files)$/)) {
    res.set('Cache-Control', 'public, max-age=3600, s-maxage=3600');
    return next();
  }

  // Category and listing pages - cache for 1 hour
  if (req.path.match(/\/(categories|search|browse)\b/)) {
    res.set('Cache-Control', 'public, max-age=3600, s-maxage=3600');
    return next();
  }

  // Home page - cache for 5 minutes (updated more often)
  if (req.path === '/' || req.path === '/index') {
    res.set('Cache-Control', 'public, max-age=300, s-maxage=300');
    return next();
  }

  // User-specific pages - no cache
  if (req.path.match(/\/(dashboard|profile|settings|orders|downloads)\b/)) {
    res.set('Cache-Control', 'private, no-cache, no-store, must-revalidate');
    res.set('Pragma', 'no-cache');
    res.set('Expires', '0');
    return next();
  }

  // Default - short cache
  res.set('Cache-Control', 'public, max-age=300');
  next();
};

/**
 * Conditional Request Optimization
 * Handle If-Modified-Since and ETag headers
 */
const conditionalRequestMiddleware = (req, res, next) => {
  // Generate ETag for HTML responses
  const originalJson = res.json;
  res.json = function(data) {
    const crypto = require('crypto');
    const hash = crypto.createHash('sha256').update(JSON.stringify(data)).digest('hex');
    res.set('ETag', `"${hash}"`);
    return originalJson.call(this, data);
  };

  next();
};

/**
 * Response Time Tracking
 * Monitor and log slow responses for performance optimization
 */
const responseTimeMiddleware = (req, res, next) => {
  const start = process.hrtime.bigint();

  res.on('finish', () => {
    const end = process.hrtime.bigint();
    const duration = Number(end - start) / 1000000; // Convert to milliseconds

    // Log slow responses (> 1 second)
    if (duration > 1000) {
      console.warn(`⚠️  SLOW: ${req.method} ${req.path} - ${duration.toFixed(2)}ms`);
    }

    // Set X-Response-Time header
    res.set('X-Response-Time', `${duration.toFixed(2)}ms`);

    // Log to performance metrics
    if (req.app.locals.performanceMetrics) {
      req.app.locals.performanceMetrics.push({
        path: req.path,
        method: req.method,
        duration,
        timestamp: new Date()
      });
    }
  });

  next();
};

/**
 * Image Optimization Middleware
 * Add responsive image hints and optimization directives
 */
const imageOptimizationMiddleware = (req, res, next) => {
  if (req.path.match(/\.(jpg|jpeg|png|gif|webp)$/i)) {
    // Allow browsers to request optimal image sizes
    res.set('Accept-Ranges', 'bytes');
    
    // Set proper headers for image caching
    res.set('Cache-Control', 'public, max-age=31536000, immutable');
  }
  next();
};

/**
 * Database Query Optimization Tracker
 * Monitor slow database queries
 */
const dbQueryTracker = (queryTime = 100) => {
  return (req, res, next) => {
    const mongoose = require('mongoose');

    // Hook into mongoose to track queries
    if (!mongoose._queryTracker) {
      mongoose._queryTracker = true;

      mongoose.connection.on('open', () => {
        const originalExec = mongoose.Query.prototype.exec;
        mongoose.Query.prototype.exec = async function(...args) {
          const start = Date.now();
          const result = await originalExec.apply(this, args);
          const duration = Date.now() - start;

          if (duration > queryTime) {
            const query = this.getQuery();
            console.warn(`📊 SLOW QUERY (${duration}ms):`, {
              collection: this.model?.collection?.name,
              query,
              method: this.op
            });
          }

          return result;
        };
      });
    }

    next();
  };
};

/**
 * Core Web Vitals Tracking
 * Helper to measure and report Core Web Vitals
 */
const coreWebVitalsHelper = {
  /**
   * Inject Web Vitals tracking script to frontend
   * Returns HTML snippet to add to template
   */
  getInjectScript: () => `
    <!-- Google Analytics & Web Vitals -->
    <script async src="https://www.googletagmanager.com/gtag/js?id=GA_MEASUREMENT_ID"></script>
    <script>
      window.dataLayer = window.dataLayer || [];
      function gtag(){dataLayer.push(arguments);}
      gtag('js', new Date());
      gtag('config', 'GA_MEASUREMENT_ID');

      // Web Vitals tracking
      import('https://cdn.jsdelivr.net/npm/web-vitals').then(({ getCLS, getFID, getFCP, getLCP, getTTFB }) => {
        getCLS(metric => gtag('event', 'page_view', { 'cls_value': metric.value }));
        getFID(metric => gtag('event', 'page_view', { 'fid_value': metric.value }));
        getFCP(metric => gtag('event', 'page_view', { 'fcp_value': metric.value }));
        getLCP(metric => gtag('event', 'page_view', { 'lcp_value': metric.value }));
        getTTFB(metric => gtag('event', 'page_view', { 'ttfb_value': metric.value }));
      });
    </script>
  `,

  /**
   * Server-side helper to recommend optimizations
   */
  analyzeResponse: (duration, size) => {
    const recommendations = [];
    
    if (duration > 3000) recommendations.push('Response too slow - optimize DB queries');
    if (size > 1000000) recommendations.push('Response too large - consider gzip compression');
    if (duration > 1000 && size > 500000) recommendations.push('Large + Slow - optimize content delivery');
    
    return recommendations;
  }
};

/**
 * SEO Metadata Injection Middleware
 * Automatically add meta tags based on response content
 */
const seoMetadataInjection = (req, res, next) => {
  // Store original send method
  const originalSend = res.send;

  res.send = function(data) {
    // Only inject for HTML responses
    if (typeof data === 'string' && data.includes('<!DOCTYPE') || data.includes('<html')) {
      const seoHead = `
    <!-- SEO Meta Tags -->
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="theme-color" content="#007bff">
    <link rel="canonical" href="${req.protocol}://${req.get('host')}${req.originalUrl}">
    
    <!-- Open Graph Meta Tags -->
    <meta property="og:type" content="website">
    <meta property="og:url" content="${req.protocol}://${req.get('host')}${req.originalUrl}">
    <meta property="og:site_name" content="Vidyari">
    
    <!-- Twitter Card Meta Tags -->
    <meta name="twitter:card" content="summary_large_image">
    <meta name="twitter:creator" content="@vidyari">
    
    <!-- Additional SEO -->
    <meta name="language" content="English">
    <meta name="robots" content="index, follow, max-image-preview:large, max-snippet:-1, max-video-preview:-1">
    <meta name="googlebot" content="index, follow, max-image-preview:large, max-snippet:-1, max-video-preview:-1">
      `;

      // Inject before </head>
      data = data.replace('</head>', seoHead + '\n  </head>');
    }

    return originalSend.call(this, data);
  };

  next();
};

/**
 * Comprehensive Performance Monitoring Dashboard
 */
const initPerformanceMonitoring = (app) => {
  if (!app.locals.performanceMetrics) {
    app.locals.performanceMetrics = [];
  }

  // Endpoint to get performance stats
  app.get('/admin/performance-stats', (req, res) => {
    const metrics = app.locals.performanceMetrics;
    const stats = {
      totalRequests: metrics.length,
      slowRequests: metrics.filter(m => m.duration > 1000).length,
      averageResponseTime: metrics.reduce((sum, m) => sum + m.duration, 0) / metrics.length || 0,
      slowestEndpoints: metrics
        .sort((a, b) => b.duration - a.duration)
        .slice(0, 10)
        .map(m => ({ path: m.path, duration: m.duration.toFixed(2) + 'ms' }))
    };

    res.json(stats);
  });

  // Clear old metrics (keep last 10000 requests)
  setInterval(() => {
    if (app.locals.performanceMetrics.length > 10000) {
      app.locals.performanceMetrics = app.locals.performanceMetrics.slice(-10000);
    }
  }, 60000); // Every minute
};

module.exports = {
  compressionMiddleware,
  cacheControlMiddleware,
  conditionalRequestMiddleware,
  responseTimeMiddleware,
  imageOptimizationMiddleware,
  dbQueryTracker,
  coreWebVitalsHelper,
  seoMetadataInjection,
  initPerformanceMonitoring
};

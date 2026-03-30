/**
 * SEO Routes - Sitemap, Robots.txt, Feed
 * Location: /routes/seoRoutes.js
 */

const express = require('express');
const router = express.Router();
const Course = require('../models/course');
const File = require('../models/file');
const User = require('../models/userData');

/**
 * Dynamic XML Sitemap for Courses
 * GET /sitemap-courses.xml
 */
router.get('/sitemap-courses.xml', async (req, res) => {
  try {
    const baseUrl = 'https://vidyari.com';
    const courses = await Course.find({ published: true })
      .select('slug updatedAt createdAt')
      .lean();

    let xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
    xml += '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n';

    courses.forEach(course => {
      const lastmod = course.updatedAt ? course.updatedAt.toISOString().split('T')[0] : course.createdAt.toISOString().split('T')[0];
      xml += `  <url>\n`;
      xml += `    <loc>${baseUrl}/course/${course.slug}</loc>\n`;
      xml += `    <lastmod>${lastmod}</lastmod>\n`;
      xml += `    <changefreq>weekly</changefreq>\n`;
      xml += `    <priority>0.8</priority>\n`;
      xml += `  </url>\n`;
    });

    xml += '</urlset>';
    res.header('Content-Type', 'application/xml');
    res.send(xml);
  } catch (error) {
    console.error('📍 Sitemap generation error:', error);
    res.status(500).send('Error generating sitemap');
  }
});

/**
 * Dynamic XML Sitemap for Files
 * GET /sitemap-files.xml
 */
router.get('/sitemap-files.xml', async (req, res) => {
  try {
    const baseUrl = 'https://vidyari.com';
    const files = await File.find({ published: true })
      .select('slug updatedAt createdAt')
      .lean();

    let xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
    xml += '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n';

    files.forEach(file => {
      const lastmod = file.updatedAt ? file.updatedAt.toISOString().split('T')[0] : file.createdAt.toISOString().split('T')[0];
      xml += `  <url>\n`;
      xml += `    <loc>${baseUrl}/file/${file.slug}</loc>\n`;
      xml += `    <lastmod>${lastmod}</lastmod>\n`;
      xml += `    <changefreq>monthly</changefreq>\n`;
      xml += `    <priority>0.6</priority>\n`;
      xml += `  </url>\n`;
    });

    xml += '</urlset>';
    res.header('Content-Type', 'application/xml');
    res.send(xml);
  } catch (error) {
    console.error('📍 Sitemap generation error:', error);
    res.status(500).send('Error generating sitemap');
  }
});

/**
 * Dynamic XML Sitemap for Instructors
 * GET /sitemap-instructors.xml
 */
router.get('/sitemap-instructors.xml', async (req, res) => {
  try {
    const baseUrl = 'https://vidyari.com';
    const instructors = await User.find({ role: 'instructor', isActive: true })
      .select('slug updatedAt')
      .lean();

    let xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
    xml += '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n';

    instructors.forEach(instructor => {
      const lastmod = instructor.updatedAt.toISOString().split('T')[0];
      xml += `  <url>\n`;
      xml += `    <loc>${baseUrl}/instructor/${instructor.slug}</loc>\n`;
      xml += `    <lastmod>${lastmod}</lastmod>\n`;
      xml += `    <changefreq>monthly</changefreq>\n`;
      xml += `    <priority>0.7</priority>\n`;
      xml += `  </url>\n`;
    });

    xml += '</urlset>';
    res.header('Content-Type', 'application/xml');
    res.send(xml);
  } catch (error) {
    console.error('📍 Sitemap generation error:', error);
    res.status(500).send('Error generating sitemap');
  }
});

/**
 * Master Sitemap Index
 * GET /sitemap.xml
 */
router.get('/sitemap.xml', (req, res) => {
  const baseUrl = 'https://vidyari.com';
  const today = new Date().toISOString().split('T')[0];

  let xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
  xml += '<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n';
  xml += `  <sitemap>\n`;
  xml += `    <loc>${baseUrl}/sitemap-courses.xml</loc>\n`;
  xml += `    <lastmod>${today}</lastmod>\n`;
  xml += `  </sitemap>\n`;
  xml += `  <sitemap>\n`;
  xml += `    <loc>${baseUrl}/sitemap-files.xml</loc>\n`;
  xml += `    <lastmod>${today}</lastmod>\n`;
  xml += `  </sitemap>\n`;
  xml += `  <sitemap>\n`;
  xml += `    <loc>${baseUrl}/sitemap-instructors.xml</loc>\n`;
  xml += `    <lastmod>${today}</lastmod>\n`;
  xml += `  </sitemap>\n`;
  xml += '</sitemapindex>';

  res.header('Content-Type', 'application/xml');
  res.send(xml);
});

/**
 * Robots.txt with dynamic rules
 * GET /robots.txt
 */
router.get('/robots.txt', (req, res) => {
  const robots = `# Vidyari Robots.txt
# Generated for optimal SEO crawling

User-agent: *
Allow: /
Disallow: /admin/
Disallow: /api/internal/
Disallow: /admin-panel/
Disallow: /checkout/process
Disallow: /payment/verify
Disallow: /auth/
Disallow: /user/private/
Disallow: /*?sort=
Disallow: /*?page=
Disallow: /temp/
Disallow: /cache/
Disallow: /private/

# Allow important bots
Allow: /upload-area/public/

# Crawl-delay for specific bots
User-agent: AhrefsBot
Crawl-delay: 10
Request-rate: 1/10

User-agent: SemrushBot
Crawl-delay: 5
Request-rate: 1/5

# High priority crawling for Google
User-agent: Googlebot
Crawl-delay: 1
Allow: /

# Block bad actors
User-agent: MJ12bot
Disallow: /

User-agent: AhrefsBot
Disallow: /

# Sitemaps
Sitemap: https://vidyari.com/sitemap.xml
Sitemap: https://vidyari.com/sitemap-courses.xml
Sitemap: https://vidyari.com/sitemap-files.xml
Sitemap: https://vidyari.com/sitemap-instructors.xml
`;

  res.header('Content-Type', 'text/plain');
  res.send(robots);
});

/**
 * RSS Feed for Latest Courses
 * GET /feed/courses.xml
 */
router.get('/feed/courses.xml', async (req, res) => {
  try {
    const baseUrl = 'https://vidyari.com';
    const courses = await Course.find({ published: true })
      .populate('instructor', 'name email slug')
      .sort({ createdAt: -1 })
      .limit(50)
      .lean();

    const today = new Date().toISOString();

    let xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
    xml += '<rss version="2.0" xmlns:content="http://purl.org/rss/1.0/modules/content/" xmlns:atom="http://www.w3.org/2005/Atom">\n';
    xml += '<channel>\n';
    xml += '<title>Vidyari - Latest Courses</title>\n';
    xml += `<link>${baseUrl}</link>\n`;
    xml += '<description>Discover the latest online courses on Vidyari</description>\n';
    xml += `<lastBuildDate>${today}</lastBuildDate>\n`;
    xml += `<atom:link href="${baseUrl}/feed/courses.xml" rel="self" type="application/rss+xml" />\n`;

    courses.forEach(course => {
      xml += '<item>\n';
      xml += `<title><![CDATA[${course.title}]]></title>\n`;
      xml += `<link>${baseUrl}/course/${course.slug}</link>\n`;
      xml += `<guid>${baseUrl}/course/${course.slug}</guid>\n`;
      xml += `<description><![CDATA[${course.description?.substring(0, 200)}...]]></description>\n`;
      xml += `<pubDate>${course.createdAt.toUTCString()}</pubDate>\n`;
      xml += `<author>${course.instructor?.email}</author>\n`;
      xml += `<category>${course.category}</category>\n`;
      xml += '</item>\n';
    });

    xml += '</channel>\n';
    xml += '</rss>';

    res.header('Content-Type', 'application/xml');
    res.send(xml);
  } catch (error) {
    console.error('📍 RSS feed error:', error);
    res.status(500).send('Error generating feed');
  }
});

/**
 * Security.txt for security researchers
 * GET /.well-known/security.txt
 */
router.get('/.well-known/security.txt', (req, res) => {
  const security = `Contact: security@vidyari.com
Expires: ${new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString()}
Preferred-Languages: en, hi
`;

  res.header('Content-Type', 'text/plain');
  res.send(security);
});

/**
 * Security Policy Report
 * Used for CSP violations, etc.
 */
router.post('/api/security/report', (req, res) => {
  const report = req.body;
  console.error('🚨 Security Report:', report);
  // In production, send to security monitoring service
  res.json({ success: true });
});

module.exports = router;

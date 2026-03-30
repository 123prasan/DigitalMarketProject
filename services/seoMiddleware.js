/**
 * SEO Middleware - Handles meta tags, structured data, caching
 * Location: /services/seoMiddleware.js
 */

const mongoose = require('mongoose');

/**
 * Generate meta tags based on page type
 */
const generateMetaTags = (pageType, data = {}) => {
  const baseUrl = 'https://vidyari.com';
  const defaultImage = 'https://d3tonh6o5ach9f.cloudfront.net/og-image.jpg';

  const metaTags = {
    home: {
      title: 'Online Courses & Digital Resources | Vidyari - Learn from Experts',
      description: 'Find thousands of professional online courses and digital resources. Learn new skills from industry experts. Affordable, accessible, and result-driven learning.',
      keywords: 'online courses, digital learning, skill development, professional courses, educational resources',
      ogTitle: 'Vidyari - Premium Online Courses & Learning Platform',
      ogDescription: 'Access thousands of courses and resources. Learn at your pace from industry experts.',
      ogImage: defaultImage,
      twitterCard: 'summary_large_image',
      author: 'Vidyari Team',
      robots: 'index, follow, max-image-preview:large, max-snippet:-1, max-video-preview:-1'
    },

    course: {
      title: `${data.title} | Online Course ${new Date().getFullYear()} | Vidyari`,
      description: `Learn ${data.title} from expert instructor ${data.instructor}. ${data.description?.substring(0, 100)}... ${data.studentCount}+ students enrolled. Certificate included.`,
      keywords: `${data.title}, ${data.category} course, learn ${data.category}, online ${data.category}, best ${data.category} course`,
      ogTitle: `${data.title} - Professional Online Course`,
      ogDescription: `Master ${data.title} from expert instructors. ${data.studentCount}+ students learning. Affordable rates.`,
      ogImage: data.thumbnail || defaultImage,
      twitterCard: 'summary_large_image',
      author: data.instructor,
      robots: 'index, follow, max-image-preview:large'
    },

    file: {
      title: `${data.name} | Download Digital Resource | Vidyari`,
      description: `Download ${data.name}. ${data.description?.substring(0, 100)}... Trusted by ${data.downloadCount}+ users. Secure & instant access.`,
      keywords: `${data.name}, download, digital resource, ${data.category}, ${data.fileType}`,
      ogTitle: `${data.name} - Quality Digital Resource`,
      ogDescription: `Get ${data.name}. High-quality resource used by thousands. Download now.`,
      ogImage: data.preview || defaultImage,
      twitterCard: 'summary',
      author: data.uploader,
      robots: 'index, follow'
    },

    instructor: {
      title: `${data.name} - Online Instructor | Courses & Resources | Vidyari`,
      description: `Learn from ${data.name} on Vidyari. ${data.bio?.substring(0, 100)}... ${data.courseCount}+ courses with ${data.totalStudents}+ students.`,
      keywords: `${data.name}, instructor, courses by ${data.name}, online learning, education`,
      ogTitle: `${data.name} - Professional Instructor`,
      ogDescription: `Follow ${data.name} and learn from their expertise. Multiple courses available.`,
      ogImage: data.avatar || defaultImage,
      twitterCard: 'summary',
      author: data.name,
      robots: 'index, follow'
    },

    category: {
      title: `${data.categoryName} Courses & Resources | Learn Online | Vidyari`,
      description: `Explore ${data.courseCount}+ ${data.categoryName.toLowerCase()} courses. Learn from expert instructors. ${data.studentCount}+ students already learning. Start free trial today.`,
      keywords: `${data.categoryName.toLowerCase()} courses, learn ${data.categoryName.toLowerCase()}, ${data.categoryName.toLowerCase()} online, best ${data.categoryName.toLowerCase()} courses`,
      ogTitle: `${data.categoryName} Learning on Vidyari`,
      ogDescription: `Browse ${data.courseCount}+ ${data.categoryName.toLowerCase()} courses. Expert instructors. Affordable pricing.`,
      ogImage: data.categoryImage || defaultImage,
      twitterCard: 'summary',
      robots: 'index, follow'
    }
  };

  return metaTags[pageType] || metaTags.home;
};

/**
 * Generate Course Schema (JSON-LD)
 */
const generateCourseSchema = (course, instructor, baseUrl = 'https://vidyari.com') => {
  const schema = {
    '@context': 'https://schema.org',
    '@type': 'Course',
    '@id': `${baseUrl}/course/${course.slug}`,
    name: course.title,
    description: course.description,
    url: `${baseUrl}/course/${course.slug}`,
    image: course.thumbnail || `${baseUrl}/images/course-placeholder.jpg`,
    courseCode: course._id.toString(),
    educationLevel: course.level || 'Beginner',
    instructor: {
      '@type': 'Person',
      name: instructor?.name || 'Expert Instructor',
      url: `${baseUrl}/instructor/${instructor?._id || ''}`,
      image: instructor?.avatar || `${baseUrl}/images/avatar-placeholder.jpg`
    },
    provider: {
      '@type': 'Organization',
      name: 'Vidyari',
      url: baseUrl,
      sameAs: ['https://twitter.com/vidyari', 'https://www.linkedin.com/company/vidyari']
    },
    offers: {
      '@type': 'Offer',
      url: `${baseUrl}/course/${course.slug}`,
      price: course.price || 0,
      priceCurrency: course.currency || 'INR',
      category: course.category,
      availability: 'https://schema.org/InStock',
      validFrom: course.createdAt.toISOString()
    },
    aggregateRating: course.averageRating ? {
      '@type': 'AggregateRating',
      ratingValue: course.averageRating,
      ratingCount: course.reviewCount || 0,
      reviewCount: course.reviewCount || 0
    } : undefined,
    coursePrerequisites: course.prerequisites || [],
    duration: `PT${course.duration || 0}H`,
    learningResourceType: 'Course'
  };

  // Remove undefined properties
  Object.keys(schema).forEach(key => schema[key] === undefined && delete schema[key]);
  return schema;
};

/**
 * Generate File/CreativeWork Schema (JSON-LD)
 */
const generateFileSchema = (file, uploader, baseUrl = 'https://vidyari.com') => {
  return {
    '@context': 'https://schema.org',
    '@type': 'CreativeWork',
    '@id': `${baseUrl}/file/${file.slug}`,
    name: file.name,
    description: file.description,
    url: `${baseUrl}/file/${file.slug}`,
    image: file.preview || `${baseUrl}/images/file-placeholder.jpg`,
    creator: {
      '@type': 'Person',
      name: uploader?.name || 'Creator',
      url: uploader?._id ? `${baseUrl}/profile/${uploader._id}` : undefined
    },
    datePublished: file.createdAt.toISOString(),
    dateModified: file.updatedAt.toISOString(),
    inLanguage: 'en-IN',
    fileFormat: file.fileType,
    aggregateRating: file.averageRating ? {
      '@type': 'AggregateRating',
      ratingValue: file.averageRating,
      ratingCount: file.downloadCount || 0
    } : undefined,
    offers: {
      '@type': 'Offer',
      price: file.price || 0,
      priceCurrency: file.currency || 'INR'
    }
  };
};

/**
 * Generate Organization Schema (For homepage)
 */
const generateOrganizationSchema = (baseUrl = 'https://vidyari.com') => {
  return {
    '@context': 'https://schema.org',
    '@type': 'Organization',
    name: 'Vidyari',
    url: baseUrl,
    logo: `${baseUrl}/images/logo.png`,
    description: 'Premium online learning platform with courses and digital resources',
    foundingDate: '2024',
    contactPoint: {
      '@type': 'ContactPoint',
      contactType: 'Customer Support',
      email: 'support@vidyari.com',
      availableLanguage: ['en', 'hi']
    },
    sameAs: [
      'https://twitter.com/vidyari',
      'https://www.linkedin.com/company/vidyari',
      'https://www.facebook.com/vidyari'
    ]
  };
};

/**
 * Generate BreadcrumbList Schema
 */
const generateBreadcrumbSchema = (breadcrumbs, baseUrl = 'https://vidyari.com') => {
  return {
    '@context': 'https://schema.org',
    '@type': 'BreadcrumbList',
    itemListElement: breadcrumbs.map((crumb, index) => ({
      '@type': 'ListItem',
      position: index + 1,
      name: crumb.name,
      item: `${baseUrl}${crumb.url}`
    }))
  };
};

/**
 * Express middleware to add SEO data to res.locals
 */
const seoMiddleware = (req, res, next) => {
  const baseUrl = 'https://vidyari.com';

  res.locals = res.locals || {};
  res.locals.seo = {
    metaTags: {},
    schemas: [],
    openGraph: {}
  };

  res.locals.setMetaTags = (pageType, data) => {
    res.locals.seo.metaTags = generateMetaTags(pageType, data);
  };

  res.locals.addSchema = (schema) => {
    res.locals.seo.schemas.push(schema);
  };

  res.locals.generateCourseSchema = (course, instructor) => 
    generateCourseSchema(course, instructor, baseUrl);

  res.locals.generateFileSchema = (file, uploader) => 
    generateFileSchema(file, uploader, baseUrl);

  res.locals.generateOrganizationSchema = () => 
    generateOrganizationSchema(baseUrl);

  res.locals.generateBreadcrumbSchema = (breadcrumbs) => 
    generateBreadcrumbSchema(breadcrumbs, baseUrl);

  res.locals.baseUrl = baseUrl;

  next();
};

module.exports = {
  seoMiddleware,
  generateMetaTags,
  generateCourseSchema,
  generateFileSchema,
  generateOrganizationSchema,
  generateBreadcrumbSchema
};

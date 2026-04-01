/**
 * Natural Language Processing Service
 * Extracts entities from complex queries
 * Parses: "Show me 5-hour Python courses under ₹500 with certificates"
 */

// Regex patterns for entity extraction
const entityPatterns = {
  // Duration - extracts hours/minutes
  duration: [
    /(\d+)\s*(?:hours?|hrs?|h)\s*(?:course|tutorial|lesson)?/i,
    /(?:under|less than|within|only)\s*(\d+)\s*(?:hours?|hrs?|h)/i,
    /(\d+)-\s*(?:hour|hr|h)\s*course/i,
  ],
  
  // Price - extracts currency amounts
  price: [
    /(?:under|less than|within|below|max|upto|up\s*to|₹|rs|rupees?|dollars?|\$|euros?|€)\s*[\s]*([\d,]+)/i,
    /₹\s*([\d,]+)/,
    /[\$€]\s*([\d,]+)/,
    /([\d,]+)\s*(?:rupees?|rs|₹)/i,
  ],
  
  // Language preference
  language: [
    /(?:in|language|taught in)\s+([A-Z][a-z]+(?:\s+and\s+[A-Z][a-z]+)*)/i,
    /(hindi|english|spanish|french|german|mandarin|arabic|portuguese)/i,
  ],
  
  // Level/Difficulty
  level: [
    /(?:for\s+)?(?:beginner|beginner-friendly|complete beginner|newbie|intermediate|advanced|expert|pro)/i,
    /(?:level\s*[1-5]|level\s*(?:basic|intermediate|advanced))/i,
  ],
  
  // Certificate requirement
  certificate: [
    /(?:with|including|for|and)\s+(?:a\s+)?certificate/i,
    /certificat(?:ed|ion)/i,
    /(?:get|earn)\s+(?:a\s+)?certificate/i,
  ],
  
  // Ratings
  rating: [
    /(?:rating|rated|at least|minimum|above|over)\s+(\d+(?:\.\d+)?)\s*(?:star|⭐)/i,
    /(\d+)\s*(?:star|⭐)\s*(?:course|tutorial|lesson)/i,
  ],
  
  // Project-based
  projectBased: [
    /(?:project|build|hands-on|real-world|practical)/i,
  ],
  
  // Job-ready
  jobReady: [
    /(?:job-ready|career|get\s+a\s+job|interview|hiring|employer)/i,
  ],
};

// Common entity synonyms for normalization
const entityNormalization = {
  level: {
    'beginner': ['beginner', 'newbie', 'start', 'basic', 'level 1'],
    'intermediate': ['intermediate', 'mid', 'middle', 'level 2'],
    'advanced': ['advanced', 'pro', 'expert', 'level 3'],
  },
  language: {
    'english': ['english', 'en', 'eng'],
    'hindi': ['hindi', 'हिन्दी', 'hn'],
    'spanish': ['spanish', 'es'],
    'french': ['french', 'fr'],
    'german': ['german', 'de'],
  },
};

/**
 * Extract all entities from a natural language query
 * @param {string} query - Natural language query
 * @returns {object} - Extracted entities with normalized values
 */
function extractEntities(query) {
  const entities = {
    duration: { value: null, unit: 'hours', raw: null },
    price: { value: null, currency: 'INR', raw: null },
    language: [],
    level: [],
    hasCertificate: false,
    rating: null,
    isProjectBased: false,
    isJobReady: false,
    originalQuery: query,
  };
  
  // Extract duration
  for (const pattern of entityPatterns.duration) {
    const match = query.match(pattern);
    if (match && match[1]) {
      const hours = parseInt(match[1]);
      entities.duration = {
        value: hours,
        unit: 'hours',
        raw: match[0],
      };
      break;
    }
  }
  
  // Extract price
  for (const pattern of entityPatterns.price) {
    const match = query.match(pattern);
    if (match && match[1]) {
      const priceStr = match[1].replace(/,/g, '');
      const price = parseInt(priceStr);
      
      // Detect currency
      let currency = 'INR';
      if (query.includes('$')) currency = 'USD';
      if (query.includes('€')) currency = 'EUR';
      if (query.includes('₹') || query.includes('rupees') || query.includes('rs')) currency = 'INR';
      
      entities.price = {
        value: price,
        currency,
        raw: match[0],
      };
      break;
    }
  }
  
  // Extract language
  for (const pattern of entityPatterns.language) {
    const matches = query.matchAll(new RegExp(pattern, 'gi'));
    for (const match of matches) {
      if (match[1]) {
        const lang = match[1].toLowerCase();
        entities.language.push(lang);
      }
    }
  }
  
  // Extract level
  for (const pattern of entityPatterns.level) {
    const match = query.match(pattern);
    if (match && match[1]) {
      entities.level.push(match[1].toLowerCase());
    }
  }
  
  // Check for certificate
  for (const pattern of entityPatterns.certificate) {
    if (pattern.test(query)) {
      entities.hasCertificate = true;
      break;
    }
  }
  
  // Extract rating
  for (const pattern of entityPatterns.rating) {
    const match = query.match(pattern);
    if (match && match[1]) {
      entities.rating = parseFloat(match[1]);
      break;
    }
  }
  
  // Check for project-based
  for (const pattern of entityPatterns.projectBased) {
    if (pattern.test(query)) {
      entities.isProjectBased = true;
      break;
    }
  }
  
  // Check for job-ready
  for (const pattern of entityPatterns.jobReady) {
    if (pattern.test(query)) {
      entities.isJobReady = true;
      break;
    }
  }
  
  // Remove duplicates
  entities.language = [...new Set(entities.language)];
  entities.level = [...new Set(entities.level)];
  
  return entities;
}

/**
 * Normalize extracted entities
 * @param {object} entities - Raw extracted entities
 * @returns {object} - Normalized entities
 */
function normalizeEntities(entities) {
  const normalized = { ...entities };
  
  // Normalize levels
  if (normalized.level.length > 0) {
    const levelKey = Object.keys(entityNormalization.level).find(key =>
      entityNormalization.level[key].some(syn =>
        normalized.level.some(level => level.includes(syn) || syn.includes(level))
      )
    );
    if (levelKey) {
      normalized.level = [levelKey];
    }
  }
  
  // Normalize languages
  normalized.language = normalized.language.map(lang => {
    for (const [normalized_lang, synonyms] of Object.entries(entityNormalization.language)) {
      if (synonyms.some(syn => lang.includes(syn) || syn.includes(lang))) {
        return normalized_lang;
      }
    }
    return lang;
  });
  
  return normalized;
}

/**
 * Convert extracted entities to filter object
 * @param {object} entities - Extracted entities
 * @returns {object} - Filter object for database query
 */
function entitiesToFilter(entities) {
  const filter = {};
  
  // Duration filter
  if (entities.duration.value) {
    filter.durationMax = entities.duration.value;
  }
  
  // Price filter
  if (entities.price.value) {
    filter.priceMax = entities.price.value;
  }
  
  // Language filter
  if (entities.language.length > 0) {
    filter.language = entities.language;
  }
  
  // Level filter
  if (entities.level.length > 0) {
    filter.level = entities.level[0]; // Use first detected level
  }
  
  // Certificate filter
  if (entities.hasCertificate) {
    filter.certification = 'Certified';
  }
  
  // Rating filter
  if (entities.rating) {
    filter.minRating = entities.rating;
  }
  
  // Format filter
  if (entities.isProjectBased) {
    filter.format = 'Project';
  }
  
  return filter;
}

/**
 * Parse natural language query and return structured data
 * @param {string} query - Natural language query
 * @returns {object} - Parsed query with entities and filters
 */
function parseNaturalLanguageQuery(query) {
  const entities = extractEntities(query);
  const normalized = normalizeEntities(entities);
  const filter = entitiesToFilter(normalized);
  
  return {
    rawQuery: query,
    entities: normalized,
    filters: filter,
    summary: generateQuerySummary(normalized),
  };
}

/**
 * Generate human-readable summary of parsed query
 * @param {object} entities - Normalized entities
 * @returns {string} - Summary string
 */
function generateQuerySummary(entities) {
  const parts = [];
  
  if (entities.level.length > 0) {
    parts.push(`${entities.level[0]} level`);
  }
  
  if (entities.duration.value) {
    parts.push(`up to ${entities.duration.value} hours`);
  }
  
  if (entities.price.value) {
    parts.push(`under ₹${entities.price.value}`);
  }
  
  if (entities.hasCertificate) {
    parts.push('with certificate');
  }
  
  if (entities.isProjectBased) {
    parts.push('project-based');
  }
  
  if (entities.isJobReady) {
    parts.push('job-ready');
  }
  
  if (entities.language.length > 0) {
    parts.push(`in ${entities.language.join(' & ')}`);
  }
  
  return parts.length > 0 ? parts.join(', ') : 'No specific requirements detected';
}

module.exports = {
  extractEntities,
  normalizeEntities,
  entitiesToFilter,
  parseNaturalLanguageQuery,
  generateQuerySummary,
  entityPatterns,
  entityNormalization,
};

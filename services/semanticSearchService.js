/**
 * Semantic Search Service
 * Understands meaning and context, not just keywords
 * Maps queries to related concepts and synonyms
 */

// Semantic keyword mapping - expand keywords to understand meaning
const semanticMap = {
  // Web Development
  'python for web': ['django', 'flask', 'fastapi', 'python', 'web development', 'backend'],
  'web development': ['html', 'css', 'javascript', 'react', 'vue', 'angular', 'nodejs', 'express'],
  'frontend': ['react', 'vue', 'angular', 'html', 'css', 'javascript', 'responsive design', 'ui/ux'],
  'backend': ['nodejs', 'express', 'python', 'django', 'java', 'spring', 'database', 'api'],
  'fullstack': ['react', 'nodejs', 'mongodb', 'express', 'javascript', 'html', 'css', 'database'],
  
  // Design & Animation
  'learn animation': ['video courses', 'motion graphics', 'after effects', 'css animation', 'animations', 'visual design'],
  'ui/ux': ['design', 'figma', 'adobe xd', 'user experience', 'interface design', 'prototyping'],
  'graphic design': ['photoshop', 'illustrator', 'canva', 'design tools', 'visual design'],
  
  // Data & AI
  'data science': ['python', 'machine learning', 'pandas', 'numpy', 'analysis', 'statistics', 'sql'],
  'machine learning': ['python', 'tensorflow', 'keras', 'scikit-learn', 'neural networks', 'ai', 'deep learning'],
  'ai': ['machine learning', 'nlp', 'computer vision', 'algorithms', 'neural networks'],
  
  // Mobile
  'mobile development': ['react native', 'flutter', 'ios', 'android', 'swift', 'kotlin', 'app development'],
  'react native': ['mobile app', 'javascript', 'cross-platform', 'ios', 'android'],
  'flutter': ['mobile app', 'dart', 'cross-platform', 'ios', 'android'],
  
  // Cloud & DevOps
  'cloud': ['aws', 'azure', 'gcp', 'docker', 'kubernetes', 'devops', 'scalability'],
  'devops': ['docker', 'kubernetes', 'ci/cd', 'jenkins', 'automation', 'deployment'],
  'docker': ['containers', 'kubernetes', 'deployment', 'microservices', 'devops'],
  
  // Database
  'database': ['sql', 'mongodb', 'postgres', 'mysql', 'redis', 'nosql', 'data management'],
  'sql': ['database', 'postgres', 'mysql', 'queries', 'relational database'],
  'mongodb': ['database', 'nosql', 'json', 'collections', 'document database'],
  
  // Programming Languages
  'javascript': ['node.js', 'react', 'vue', 'web development', 'es6', 'dom', 'async'],
  'python': ['data science', 'django', 'flask', 'machine learning', 'automation'],
  'java': ['spring', 'backend', 'android', 'oop', 'enterprise'],
  'go': ['backend', 'microservices', 'concurrency', 'performance'],
  'rust': ['performance', 'systems programming', 'safety', 'backend'],
  
  // Business & Soft Skills
  'business': ['entrepreneurship', 'marketing', 'finance', 'management', 'strategy'],
  'marketing': ['digital marketing', 'seo', 'social media', 'content marketing', 'branding'],
  'leadership': ['management', 'communication', 'team building', 'motivation'],
  'communication': ['presentation', 'writing', 'soft skills', 'leadership'],
  
  // Common Typos/Variations
  'js': ['javascript', 'node.js', 'react', 'web development'],
  'css': ['css', 'scss', 'tailwind', 'bootstrap', 'styling', 'sass'],
  'html': ['html', 'semantic html', 'forms', 'accessibility'],
  'ml': ['machine learning', 'models', 'ai', 'data science'],
  'ds': ['data science', 'analysis', 'python', 'statistics'],
  'oop': ['object-oriented', 'design patterns', 'java', 'programming'],
  'api': ['rest api', 'graphql', 'integration', 'backend'],
};

// Intent mappings - understand what user wants to do
const intentMap = {
  'learn': 'educational',
  'master': 'advanced-learning',
  'beginners guide': 'beginner',
  'complete': 'comprehensive',
  'quick': 'short-duration',
  'project': 'project-based',
  'build': 'hands-on',
  'practical': 'hands-on',
  'real-world': 'practical',
  'get job': 'career-focused',
  'interview prep': 'certification',
  'certification': 'certification',
  'bootcamp': 'intensive',
};

// Skill pathway mappings
const skillPathways = {
  'web development': {
    beginner: ['HTML & CSS Basics', 'JavaScript Fundamentals', 'Responsive Design'],
    intermediate: ['React Basics', 'Backend with Node.js', 'Database Design'],
    advanced: ['Full-Stack Architecture', 'Performance Optimization', 'DevOps & Deployment'],
  },
  'data science': {
    beginner: ['Python Basics', 'Pandas & Data Cleaning', 'Statistics Fundamentals'],
    intermediate: ['Machine Learning Basics', 'Data Visualization', 'SQL & Databases'],
    advanced: ['Deep Learning', 'NLP', 'Big Data & Spark'],
  },
  'mobile development': {
    beginner: ['Mobile Basics', 'React Native or Flutter Setup', 'UI Design'],
    intermediate: ['Navigation & State', 'API Integration', 'Native Modules'],
    advanced: ['Performance', 'Testing', 'App Store Deployment'],
  },
};

/**
 * Expand a query semantically to find related concepts
 * @param {string} query - User search query
 * @returns {object} - Expanded semantic terms and related keywords
 */
function expandSemanticQuery(query) {
  const lowerQuery = query.toLowerCase().trim();
  
  // Check for exact matches in semantic map
  for (const [key, value] of Object.entries(semanticMap)) {
    if (lowerQuery === key || lowerQuery.includes(key)) {
      return {
        originalQuery: lowerQuery,
        primaryKeywords: [key],
        relatedKeywords: value,
        allKeywords: [key, ...value],
        confidence: 0.95,
      };
    }
  }
  
  // Partial matching - break query into words and find related terms
  const queryWords = lowerQuery.split(/\s+/);
  const relatedTerms = new Set();
  let confidence = 0.5;
  
  queryWords.forEach(word => {
    for (const [key, value] of Object.entries(semanticMap)) {
      if (key.includes(word) || word.includes(key.split(' ')[0])) {
        value.forEach(term => relatedTerms.add(term));
        confidence = Math.min(0.9, confidence + 0.1);
      }
    }
  });
  
  return {
    originalQuery: lowerQuery,
    primaryKeywords: queryWords,
    relatedKeywords: Array.from(relatedTerms),
    allKeywords: [...queryWords, ...Array.from(relatedTerms)],
    confidence,
  };
}

/**
 * Detect user intent from query
 * @param {string} query - User search query
 * @returns {object} - Detected intents and learning path
 */
function detectIntent(query) {
  const lowerQuery = query.toLowerCase();
  const detectedIntents = [];
  
  // Check for intent keywords
  for (const [keyword, intent] of Object.entries(intentMap)) {
    if (lowerQuery.includes(keyword)) {
      detectedIntents.push(intent);
    }
  }
  
  // Detect if it's a skill-based query
  const isSkillQuery = Object.keys(skillPathways).some(skill => 
    lowerQuery.includes(skill)
  );
  
  // Default intent if none detected
  if (detectedIntents.length === 0) {
    detectedIntents.push('educational');
  }
  
  return {
    intents: [...new Set(detectedIntents)], // Remove duplicates
    isSkillQuery,
    isCareerFocused: lowerQuery.includes('job') || lowerQuery.includes('career'),
    isCertification: lowerQuery.includes('certificate') || lowerQuery.includes('certified'),
  };
}

/**
 * Get recommended learning path
 * @param {string} skill - Skill name
 * @param {string} level - beginner/intermediate/advanced
 * @returns {array} - Recommended course sequence
 */
function getLearningPath(skill, level = 'beginner') {
  const skillKey = Object.keys(skillPathways).find(key => 
    skill.toLowerCase().includes(key) || key.includes(skill.toLowerCase())
  );
  
  if (skillKey && skillPathways[skillKey][level]) {
    return skillPathways[skillKey][level];
  }
  
  return [];
}

/**
 * Build semantic search filter based on query
 * @param {string} query - User search query
 * @returns {object} - Filter suggestions based on semantics
 */
function buildSemanticFilter(query) {
  const expanded = expandSemanticQuery(query);
  const intent = detectIntent(query);
  const filters = {};
  
  // Suggest difficulty level based on intent
  if (intent.intents.includes('beginner')) {
    filters.difficulty = 'Beginner';
  } else if (intent.intents.includes('advanced-learning')) {
    filters.difficulty = 'Advanced';
  }
  
  // Suggest format based on intent
  if (intent.intents.includes('project-based')) {
    filters.format = 'Project';
  } else if (intent.intents.includes('quick') || query.toLowerCase().includes('quick')) {
    filters.duration = 'Short';
  }
  
  // Suggest certification if career-focused
  if (intent.isCareerFocused) {
    filters.certification = 'Certified';
  }
  
  return {
    suggestedFilters: filters,
    intents: intent.intents,
    keywords: expanded.allKeywords,
  };
}

module.exports = {
  expandSemanticQuery,
  detectIntent,
  getLearningPath,
  buildSemanticFilter,
  semanticMap,
  skillPathways,
};

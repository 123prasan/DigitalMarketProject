/**
 * Spell Correction & Expansion Service
 * Fixes typos and expands queries with related terms
 * "javscript" → "javascript"
 * "css" → "CSS, SCSS, Tailwind, Bootstrap"
 */

// Common typos and their corrections with expansions
const spellCorrections = {
  // Programming Languages
  'javscript': { correct: 'javascript', expand: ['javascript', 'typescript', 'node.js', 'react'] },
  'javascrpt': { correct: 'javascript', expand: ['javascript', 'node.js', 'frameworks'] },
  'java script': { correct: 'javascript', expand: ['javascript', 'node.js'] },
  'js': { correct: 'javascript', expand: ['javascript', 'es6', 'typescript', 'react', 'node.js'] },
  'pyton': { correct: 'python', expand: ['python', 'flask', 'django', 'data science'] },
  'py': { correct: 'python', expand: ['python', 'django', 'machine learning'] },
  'c++': { correct: 'cpp', expand: ['c++', 'competitive programming', 'systems'] },
  'c#': { correct: 'csharp', expand: ['c#', 'dotnet', 'unity'] },
  'golang': { correct: 'go', expand: ['go', 'backend', 'microservices'] },
  'golang': { correct: 'go', expand: ['go', 'concurrency'] },
  
  // Frontend
  'css': { correct: 'css', expand: ['css', 'scss', 'sass', 'tailwind', 'bootstrap', 'styling'] },
  'html': { correct: 'html', expand: ['html', 'semantic html', 'forms', 'accessibility'] },
  'reactjs': { correct: 'react', expand: ['react', 'jsx', 'hooks', 'redux', 'nextjs'] },
  'react js': { correct: 'react', expand: ['react', 'nextjs', 'enzyme'] },
  'vuejs': { correct: 'vue', expand: ['vue', 'nuxt', 'vuex'] },
  'vue js': { correct: 'vue', expand: ['vue', 'nuxt'] },
  'angular': { correct: 'angular', expand: ['angular', 'typescript', 'rxjs', 'routing'] },
  'angularjs': { correct: 'angular', expand: ['angular', 'modern web'] },
  'jqurey': { correct: 'jquery', expand: ['jquery', 'dom', 'ajax'] },
  
  // Backend
  'nodejs': { correct: 'node.js', expand: ['node.js', 'express', 'backend', 'javascript'] },
  'node js': { correct: 'node.js', expand: ['node.js', 'express', 'npm'] },
  'expressjs': { correct: 'express', expand: ['express', 'node.js', 'rest api', 'middleware'] },
  'express js': { correct: 'express', expand: ['express', 'backend'] },
  'djanggo': { correct: 'django', expand: ['django', 'python', 'orm', 'rest'] },
  'flak': { correct: 'flask', expand: ['flask', 'python', 'lightweight', 'micro'] },
  'springboot': { correct: 'spring boot', expand: ['spring boot', 'java', 'microservices'] },
  'spring bot': { correct: 'spring boot', expand: ['spring boot'] },
  
  // Database
  'mongodb': { correct: 'mongodb', expand: ['mongodb', 'nosql', 'json', 'aggregation', 'indexing'] },
  'postgre': { correct: 'postgresql', expand: ['postgresql', 'sql', 'advanced queries', 'json'] },
  'postgress': { correct: 'postgresql', expand: ['postgresql', 'database'] },
  'sql': { correct: 'sql', expand: ['sql', 'postgresql', 'mysql', 'queries', 'optimization'] },
  'mysql': { correct: 'mysql', expand: ['mysql', 'sql', 'php', 'wordpress'] },
  'redis': { correct: 'redis', expand: ['redis', 'caching', 'sessions', 'pub/sub'] },
  'firebase': { correct: 'firebase', expand: ['firebase', 'realtime', 'hosting', 'authentication'] },
  
  // Mobile
  'react native': { correct: 'react native', expand: ['react native', 'mobile', 'ios', 'android', 'expo'] },
  'reactnative': { correct: 'react native', expand: ['react native', 'cross-platform'] },
  'flutter': { correct: 'flutter', expand: ['flutter', 'dart', 'mobile', 'ui'] },
  'xcode': { correct: 'xcode', expand: ['xcode', 'swift', 'ios', 'development'] },
  'android studio': { correct: 'android studio', expand: ['android studio', 'kotlin', 'java'] },
  
  // DevOps & Cloud
  'docker': { correct: 'docker', expand: ['docker', 'containers', 'kubernetes', 'deployment'] },
  'dockar': { correct: 'docker', expand: ['docker', 'containerization'] },
  'kubernetes': { correct: 'kubernetes', expand: ['kubernetes', 'k8s', 'orchestration', 'docker'] },
  'k8s': { correct: 'kubernetes', expand: ['kubernetes', 'deployment'] },
  'aws': { correct: 'aws', expand: ['aws', 'cloud', 's3', 'ec2', 'lambda'] },
  'azure': { correct: 'azure', expand: ['azure', 'cloud', 'microsoft', 'devops'] },
  'gcp': { correct: 'gcp', expand: ['gcp', 'google cloud', 'cloud'] },
  
  // Data Science
  'machine learing': { correct: 'machine learning', expand: ['machine learning', 'ai', 'python', 'neural networks'] },
  'ml': { correct: 'machine learning', expand: ['machine learning', 'deep learning', 'algorithms'] },
  'ai': { correct: 'artificial intelligence', expand: ['ai', 'machine learning', 'deep learning', 'nlp'] },
  'ds': { correct: 'data science', expand: ['data science', 'python', 'statistics', 'pandas'] },
  'dl': { correct: 'deep learning', expand: ['deep learning', 'neural networks', 'tensorflow'] },
  'numpy': { correct: 'numpy', expand: ['numpy', 'arrays', 'vector operations', 'mathematics'] },
  'pandas': { correct: 'pandas', expand: ['pandas', 'dataframes', 'data cleaning', 'analysis'] },
  'scikit': { correct: 'scikit-learn', expand: ['scikit-learn', 'algorithms', 'preprocessing'] },
  'tensorflow': { correct: 'tensorflow', expand: ['tensorflow', 'keras', 'neural networks'] },
  'keras': { correct: 'keras', expand: ['keras', 'neural networks', 'sequential'] },
  'pytorch': { correct: 'pytorch', expand: ['pytorch', 'tensors', 'neural networks'] },
  'nlp': { correct: 'nlp', expand: ['nlp', 'natural language', 'text processing', 'nlp'] },
  
  // Design
  'figma': { correct: 'figma', expand: ['figma', 'design', 'prototyping', 'ui/ux'] },
  'photoshop': { correct: 'photoshop', expand: ['photoshop', 'editing', 'design'] },
  'photshop': { correct: 'photoshop', expand: ['photoshop'] },
  'illsutrator': { correct: 'illustrator', expand: ['illustrator', 'vector', 'graphics'] },
  'xd': { correct: 'adobe xd', expand: ['adobe xd', 'design', 'prototyping'] },
  'ux/ui': { correct: 'ui/ux design', expand: ['ui/ux', 'design thinking', 'prototyping', 'figma'] },
  'uiux': { correct: 'ui/ux', expand: ['ui/ux', 'design'] },
  
  // Business & Soft Skills
  'leadershi': { correct: 'leadership', expand: ['leadership', 'management', 'communication'] },
  'communiction': { correct: 'communication', expand: ['communication', 'presentation', 'writing'] },
  'wrting': { correct: 'writing', expand: ['writing', 'communication', 'content'] },
  'marketng': { correct: 'marketing', expand: ['marketing', 'digital marketing', 'seo', 'social media'] },
  'entraprenuership': { correct: 'entrepreneurship', expand: ['entrepreneurship', 'business', 'startup'] },
  
  // Other Common Errors
  'progaming': { correct: 'programming', expand: ['programming', 'languages', 'algorithms'] },
  'programing': { correct: 'programming', expand: ['programming', 'coding', 'development'] },
  'developement': { correct: 'development', expand: ['development', 'engineering'] },
  'desgin': { correct: 'design', expand: ['design', 'ui/ux', 'graphics'] },
  'bussiness': { correct: 'business', expand: ['business', 'entrepreneurship', 'management'] },
  'secruity': { correct: 'security', expand: ['security', 'encryption', 'authentication', 'hacking'] },
  'securty': { correct: 'security', expand: ['security'] },
};

// Levenshtein distance calculation for better typo detection
function levenshteinDistance(str1, str2) {
  const matrix = Array(str2.length + 1).fill(null).map(() =>
    Array(str1.length + 1).fill(null)
  );

  for (let i = 0; i <= str1.length; i += 1) {
    matrix[0][i] = i;
  }

  for (let j = 0; j <= str2.length; j += 1) {
    matrix[j][0] = j;
  }

  for (let j = 1; j <= str2.length; j += 1) {
    for (let i = 1; i <= str1.length; i += 1) {
      const indicator = str1[i - 1] === str2[j - 1] ? 0 : 1;
      matrix[j][i] = Math.min(
        matrix[j][i - 1] + 1,
        matrix[j - 1][i] + 1,
        matrix[j - 1][i - 1] + indicator
      );
    }
  }

  return matrix[str2.length][str1.length];
}

/**
 * Find similar terms in spell correction dictionary
 * Useful for terms not in our predefined list
 * @param {string} term - User input term
 * @param {number} maxDistance - Max Levenshtein distance for match
 * @returns {Array} - Array of possible corrections
 */
function findSimilarTerms(term, maxDistance = 2) {
  const lowerTerm = term.toLowerCase();
  const candidates = [];

  for (const [typo, correction] of Object.entries(spellCorrections)) {
    const distance = levenshteinDistance(lowerTerm, typo);
    if (distance <= maxDistance && distance > 0) {
      candidates.push({
        typo,
        distance,
        correction: correction.correct,
        expand: correction.expand,
      });
    }
  }

  // Sort by distance (most similar first)
  return candidates.sort((a, b) => a.distance - b.distance);
}

/**
 * Correct and expand a single term
 * @param {string} term - User input term
 * @returns {object} - Corrected spelling and expansion terms
 */
function correctAndExpand(term) {
  const lowerTerm = term.toLowerCase().trim();

  // Exact match
  if (spellCorrections[lowerTerm]) {
    return {
      original: term,
      corrected: spellCorrections[lowerTerm].correct,
      expanded: spellCorrections[lowerTerm].expand,
      confidence: 1.0,
      found: true,
    };
  }

  // Fuzzy match using Levenshtein distance
  const similar = findSimilarTerms(lowerTerm, 2);
  if (similar.length > 0) {
    const best = similar[0];
    const maxDistance = 3; // Max allowed distance
    const confidence = 1 - (best.distance / maxDistance);

    return {
      original: term,
      corrected: best.correction,
      expanded: best.expand,
      confidence: Math.max(0.5, confidence),
      found: true,
      suggestion: best.typo,
    };
  }

  // No match found
  return {
    original: term,
    corrected: lowerTerm,
    expanded: [lowerTerm],
    confidence: 0,
    found: false,
  };
}

/**
 * Correct and expand entire query (multiple terms)
 * @param {string} query - User search query
 * @returns {object} - Corrected and expanded terms
 */
function correctAndExpandQuery(query) {
  const terms = query.split(/\s+/);
  const corrections = [];
  const allExpanded = new Set();
  let totalConfidence = 0;

  terms.forEach(term => {
    const result = correctAndExpand(term);
    corrections.push(result);
    allExpanded.add(result.corrected);
    result.expanded.forEach(exp => allExpanded.add(exp));
    totalConfidence += result.confidence;
  });

  const avgConfidence = totalConfidence / terms.length;
  const correctedQuery = corrections
    .map(c => c.corrected)
    .join(' ');

  return {
    originalQuery: query,
    correctedQuery,
    corrections,
    expandedTerms: Array.from(allExpanded),
    averageConfidence: avgConfidence,
    hasTypos: corrections.some(c => c.found && c.confidence < 1),
  };
}

/**
 * Get expansion suggestions for a term
 * Useful for showing related searches
 * @param {string} term - Input term
 * @returns {Array} - Array of related terms
 */
function getExpansions(term) {
  const lowerTerm = term.toLowerCase().trim();

  // Direct match
  if (spellCorrections[lowerTerm]) {
    return spellCorrections[lowerTerm].expand;
  }

  // Fuzzy match
  const similar = findSimilarTerms(lowerTerm, 1);
  if (similar.length > 0) {
    return similar[0].expand;
  }

  return [lowerTerm]; // Return original if no match
}

module.exports = {
  correctAndExpand,
  correctAndExpandQuery,
  getExpansions,
  findSimilarTerms,
  levenshteinDistance,
  spellCorrections,
};

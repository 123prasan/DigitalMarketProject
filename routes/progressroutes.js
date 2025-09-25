const express = require('express');
const router = express.Router();
const { getProgressForCourse, updateProgress } = require('../controllers/progresscontroller');
const authenticateJWT_user = require('./authentication/jwtAuth'); // Adjust path if needed

// Get progress for a specific course
router.get('/:courseId', authenticateJWT_user, getProgressForCourse);

// Update progress for a lesson
router.post('/update', authenticateJWT_user, updateProgress);

module.exports = router;

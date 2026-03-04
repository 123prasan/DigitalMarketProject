const requireAuth = async (req, res, next) => {
  if (!req.user) {
    // If the request is targeting an API path, always send a JSON 401 so
    // client scripts can handle it. Otherwise redirect to the login page.
    if (req.originalUrl && req.originalUrl.startsWith('/api/')) {
      return res.status(401).json({ message: 'Unauthorized' });
    }
    return res.redirect('/user-login');
  }
  next();
};

module.exports = requireAuth;
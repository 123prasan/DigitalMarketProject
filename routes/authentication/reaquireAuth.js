const requireAuth = async (req, res, next) => {
  if (!req.user) {
    // List of endpoints that should return JSON instead of redirecting
    const jsonResponseEndpoints = [
      '/api/',
      '/create-order',
      '/verify-payment',
      '/subscription/pay-now',
      '/subscription/verify-payment',
      '/check/coupon'
    ];

    // Check if this endpoint should get a JSON response
    const isJsonEndpoint = jsonResponseEndpoints.some(endpoint => 
      req.originalUrl && req.originalUrl.startsWith(endpoint)
    );

    if (isJsonEndpoint) {
      // Return JSON with login redirect info
      return res.status(401).json({ 
        success: false,
        error: 'Please log in to continue',
        requiresLogin: true,
        loginRedirectUrl: `/user-login?returnUrl=${encodeURIComponent(req.header('referer') || '/')}`
      });
    }

    // For other routes, redirect directly to login page
    const returnUrl = req.originalUrl || '/';
    return res.redirect(`/user-login?returnUrl=${encodeURIComponent(returnUrl)}`);
  }
  next();
};

module.exports = requireAuth;
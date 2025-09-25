const requireAuth = async (req, res, next) => {
  if (!req.user) {
    if (req.accepts("html")) {
      return res.redirect("/user-login");
    }
    return res.status(401).json({ message: "Unauthorized" });
  }
  next();
};

module.exports = requireAuth;
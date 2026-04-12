# LOGIN DATA PREPARATION - ANALYSIS REPORT

## CURRENT PROBLEM

**Every route manually repeats this pattern 30+ times:**

```javascript
// Pattern 1 - Simple check
let user = null;
if (req.user) {
  user = await User.findById(req.user._id).select("profilePicUrl username email");
}
res.render("page", {
  isLoggedin: !!req.user,
  profileUrl: user?.profilePicUrl || null,
  username: user?.username || null,
  useremail: user?.email || null,
  uId: user?._id || null,
});

// Pattern 2 - With caching
let user = null;
if (req.user) {
  const cacheKey = `user_${req.user._id}`;
  const cachedUser = pageCache.get(cacheKey);
  if (cachedUser) {
    user = cachedUser;
  } else {
    user = await User.findById(req.user._id).select(...).lean();
    // Convert S3 to CloudFront
    if (user.profilePicUrl?.includes("s3.")) {
      user.profilePicUrl = `${CLOUDFRONT_AVATAR_URL}/${fileName}`;
    }
    pageCache.set(cacheKey, user);
  }
}
res.render("page", {
  isLoggedin: !!req.user,
  profileUrl: user?.profilePicUrl || null,
  username: user?.username || null,
  useremail: user?.email || null,
  uId: user?._id || null,
});

// Pattern 3 - Minimal fetch
if (req.user) {
  user = await User.findById(userId).select("profilePicUrl username email");
}
```

## ISSUES

1. ❌ **Code Duplication** - Same logic in 30+ routes
2. ❌ **Inconsistent Caching** - Some routes cache, some don't
3. ❌ **Inconsistent CloudFront Conversion** - Not all routes do it
4. ❌ **Weak Login Status Check** - `isLoggedin: !!req.user` assumes req.user is always set correctly
5. ❌ **Manual Null Checking** - Every route has to check `user?.field || null`
6. ❌ **Missing uId in some routes** - Not all routes pass uId
7. ❌ **No validation** - If token is stale, still shows as logged in

## SOLUTION: Create Reusable Middleware

Instead of duplicating code everywhere, create a middleware that:

1. **Runs after `authenticateJWT_user` middleware**
2. **Prepares ALL user data in one place**
3. **Handles caching consistently**
4. **Converts CloudFront URLs automatically**
5. **Attaches to `res.locals` so all routes access it**
6. **Routes simply use:** `{ ...res.locals.userData }`

### Middleware Structure:

```javascript
// Middleware: prepareUserData
async (req, res, next) => {
  // Initialize user state
  const userData = {
    isLoggedin: false,
    profileUrl: '/images/avatar.jpg',
    username: null,
    useremail: null,
    uId: null
  };

  if (req.user) {
    try {
      // Check cache first
      const cacheKey = `user_profile_${req.user._id}`;
      let user = pageCache.get(cacheKey);
      
      // If not cached, fetch
      if (!user) {
        user = await User.findById(req.user._id)
          .select("_id profilePicUrl username email")
          .lean();
        
        // Convert S3 URLs to CloudFront
        if (user?.profilePicUrl?.includes("s3.")) {
          user.profilePicUrl = convertToCloudfront(user.profilePicUrl);
        }
        
        pageCache.set(cacheKey, user, 15 * 60);
      }
      
      // Populate userData
      if (user) {
        userData.isLoggedin = true;
        userData.profileUrl = user.profilePicUrl || '/images/avatar.jpg';
        userData.username = user.username;
        userData.useremail = user.email;
        userData.uId = user._id.toString();
      }
    } catch (err) {
      console.error('Error preparing user data:', err);
      // Fallback: clear user if fetch fails
      req.user = null;
    }
  }
  
  // Attach to res.locals for all views
  res.locals.userData = userData;
  next();
};
```

### How Routes Will Use It:

```javascript
// BEFORE (current - duplicated 30+ times):
let user = null;
if (req.user) {
  user = await User.findById(req.user._id).select("profilePicUrl username email");
}
res.render("page", {
  isLoggedin: !!req.user,
  profileUrl: user?.profilePicUrl || null,
  username: user?.username || null,
  useremail: user?.email || null,
  uId: user?._id || null,
});

// AFTER (clean - just one line):
res.render("page", res.locals.userData);

// OR with additional data:
res.render("page", {
  ...res.locals.userData,
  otherData: someValue,
  moreData: anotherValue
});
```

### Benefits:

✅ **Single source of truth** - All login data prepared in one place
✅ **Consistent caching** - Same logic everywhere  
✅ **Consistent CloudFront conversion** - Applied universally
✅ **Less code per route** - Remove 10+ lines per route
✅ **Better maintainability** - Fix once, applies everywhere
✅ **Better performance** - Shared caching across routes
✅ **Fewer bugs** - Less duplication = fewer mistakes

## Implementation Plan

1. Create `middleware/prepareUserData.js`
2. Add middleware to server.js after authenticateJWT_user
3. Update all routes to use `res.locals.userData`
4. Remove repeated code from all routes
5. Test all pages to verify login status consistency

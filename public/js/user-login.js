
        // const { Sign } = require("crypto");

        // DOM Elements
        const loginForm = document.getElementById("loginForm");
        const forgotPasswordForm = document.getElementById("forgotPasswordForm");
        const signupForm = document.getElementById("signupForm");

        const forgotPasswordModal = document.getElementById("forgotPasswordModal");
        const signupModal = document.getElementById("signupModal");

        const forgotPasswordLink = document.getElementById("forgotPasswordLink");
        const signupLink = document.getElementById("signupLink");
        const closeForgotModal = document.getElementById("closeForgotModal");
        const closeSignupModal = document.getElementById("closeSignupModal");

        const togglePassword = document.getElementById("togglePassword");
        const toggleSignupPassword = document.getElementById("toggleSignupPassword");

        const googleLoginBtn = document.getElementById("googleLoginBtn");

        const successToast = document.getElementById("successToast");
        const errorToast = document.getElementById("errorToast");

        // Utility Functions
        function showError(elementId, message) {
            const errorElement = document.getElementById(elementId);
            errorElement.textContent = message;
            errorElement.classList.add("show");
        }

        function hideError(elementId) {
            const errorElement = document.getElementById(elementId);
            errorElement.classList.remove("show");
        }

        function showToast(isSuccess, message) {
            const toast = isSuccess ? successToast : errorToast;
            const messageElement = isSuccess
                ? document.getElementById("successMessage")
                : document.getElementById("errorMessage");

            messageElement.textContent = message;
            toast.classList.add("show");

            setTimeout(() => {
                toast.classList.remove("show");
            }, 4000);
        }

        function setLoading(button, isLoading) {
            if (isLoading) {
                button.classList.add("loading");
                button.disabled = true;
            } else {
                button.classList.remove("loading");
                button.disabled = false;
            }
        }

        function validateEmail(email) {
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            return emailRegex.test(email);
        }

        function validatePassword(password) {
            return password.length >= 8;
        }

        function showModal(modal) {
            modal.classList.add("show");
            document.body.style.overflow = "hidden";
        }

        function hideModal(modal) {
            modal.classList.remove("show");
            document.body.style.overflow = "auto";
        }

        // Password Toggle Functionality
        function setupPasswordToggle(toggleBtn, passwordInput) {
            toggleBtn.addEventListener("click", () => {
                const type =
                    passwordInput.getAttribute("type") === "password" ? "text" : "password";
                passwordInput.setAttribute("type", type);

                const icon = toggleBtn.querySelector("i");
                if (type === "text") {
                    icon.classList.remove("fa-eye");
                    icon.classList.add("fa-eye-slash");
                } else {
                    icon.classList.remove("fa-eye-slash");
                    icon.classList.add("fa-eye");
                }
            });
        }

        // Input validation on real-time
        function setupInputValidation(inputId, errorId, validationFn, errorMessage) {
            const input = document.getElementById(inputId);

            input.addEventListener("blur", () => {
                if (input.value && !validationFn(input.value)) {
                    showError(errorId, errorMessage);
                    input.style.borderColor = "var(--error)";
                } else {
                    hideError(errorId);
                    input.style.borderColor = "";
                }
            });

            input.addEventListener("input", () => {
                if (input.style.borderColor === "var(--error)") {
                    hideError(errorId);
                    input.style.borderColor = "";
                }
            });
        }

        // Initialize Event Listeners
        document.addEventListener("DOMContentLoaded", () => {
            // Password toggle setup
            setupPasswordToggle(togglePassword, document.getElementById("password"));
            setupPasswordToggle(
                toggleSignupPassword,
                document.getElementById("signupPassword")
            );

            // Input validation setup
            setupInputValidation(
                "email",
                "emailError",
                validateEmail,
                "Please enter a valid email address"
            );
            setupInputValidation(
                "password",
                "passwordError",
                validatePassword,
                "Password must be at least 8 characters long"
            );
            setupInputValidation(
                "signupEmail",
                "signupEmailError",
                validateEmail,
                "Please enter a valid email address"
            );
            setupInputValidation(
                "signupPassword",
                "signupPasswordError",
                validatePassword,
                "Password must be at least 8 characters long"
            );
            setupInputValidation(
                "resetEmail",
                "resetEmailError",
                validateEmail,
                "Please enter a valid email address"
            );

            // Signup name validation
            setupInputValidation(
                "signupName",
                "signupNameError",
                (name) => name.trim().length >= 2,
                "Name must be at least 2 characters long"
            );

            // Confirm password validation
            const confirmPasswordInput = document.getElementById("confirmPassword");
            confirmPasswordInput.addEventListener("blur", () => {
                const password = document.getElementById("signupPassword").value;
                const confirmPassword = confirmPasswordInput.value;

                if (confirmPassword && password !== confirmPassword) {
                    showError("confirmPasswordError", "Passwords do not match");
                    confirmPasswordInput.style.borderColor = "var(--error)";
                } else {
                    hideError("confirmPasswordError");
                    confirmPasswordInput.style.borderColor = "";
                }
            });

            // Modal event listeners
            forgotPasswordLink.addEventListener("click", (e) => {
                e.preventDefault();
                showModal(forgotPasswordModal);
            });

            signupLink.addEventListener("click", (e) => {
                e.preventDefault();
                showModal(signupModal);
            });

            closeForgotModal.addEventListener("click", () => {
                hideModal(forgotPasswordModal);
            });

            closeSignupModal.addEventListener("click", () => {
                hideModal(signupModal);
            });

            // Close modals when clicking outside
            [forgotPasswordModal, signupModal].forEach((modal) => {
                modal.addEventListener("click", (e) => {
                    if (e.target === modal) {
                        hideModal(modal);
                    }
                });
            });

            // Close modals with Escape key
            document.addEventListener("keydown", (e) => {
                if (e.key === "Escape") {
                    if (forgotPasswordModal.classList.contains("show")) {
                        hideModal(forgotPasswordModal);
                    }
                    if (signupModal.classList.contains("show")) {
                        hideModal(signupModal);
                    }
                }
            });
        });

        // Form Submissions
        loginForm.addEventListener("submit", async (e) => {
            e.preventDefault();

            const email = document.getElementById("email").value.trim();
            const password = document.getElementById("password").value.trim();
            const loginBtn = document.getElementById("loginBtn");

            // Clear previous errors
            hideError("emailError");
            hideError("passwordError");

            // Validate inputs
            let hasError = false;

            if (!email) {
                showError("emailError", "Email is required");
                hasError = true;
            } else if (!validateEmail(email)) {
                showError("emailError", "Please enter a valid email address");
                hasError = true;
            }

            if (!password) {
                showError("passwordError", "Password is required");
                hasError = true;
            } else if (!validatePassword(password)) {
                showError("passwordError", "Password must be at least 8 characters long");
                hasError = true;
            }

            if (hasError) return;

            setLoading(loginBtn, true);

            try {
                const res = await fetch("/auth/login", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ email, password }),
                });

                const data = await res.json();

                if (res.status === 200) {
                    showToast(true, data.message); // success toast
                    console.log(data.message);

                    // Save JWT if needed
                    localStorage.setItem("token", data.token);

                    // Redirect to dashboard
                    setTimeout(() => {
                        window.location.href = "/";
                    }, 1500);
                } else {
                    showToast(false, data.message); // error toast
                    console.log(data.message);
                }
            } catch (error) {
                console.log(error);
                showToast(false, "Login failed. Please check your credentials.");
            } finally {
                setLoading(loginBtn, false);
            }
        });


        forgotPasswordForm.addEventListener("submit", async (e) => {
            e.preventDefault();

            const email = document.getElementById("resetEmail").value;

            // Clear previous errors
            hideError("resetEmailError");

            // Validate email
            if (!email) {
                showError("resetEmailError", "Email is required");
                return;
            }

            if (!validateEmail(email)) {
                showError("resetEmailError", "Please enter a valid email address");
                return;
            }

            const submitBtn = e.target.querySelector('button[type="submit"]');
            setLoading(submitBtn, true);

            try {
                // Simulate API call

                const res=await fetch("/auth/forgot-pass", {
                    method: "POST",
                  
                    headers: {
                        "Content-Type": "application/json",
                    },
                    body: JSON.stringify({ email:email }),
                })
                console.log("sent")
                const data = await res.json();
                console.log(data)
                if(res.status!==200){
                    showToast(false, data.message);
                    console.log(data.message)
                    return;
                }

                

                showToast(true, "Password reset link sent to your email!");
                hideModal(forgotPasswordModal);
                document.getElementById("resetEmail").value = "";
            } catch (error) {
                showToast(false, "Failed to send reset link. Please try again.");
            } finally {
                setLoading(submitBtn, false);
            }
        });
        let SignupName = document.getElementById("signupName");

        SignupName.addEventListener("input", () => {
            console.log(SignupName.value); // fixed

            fetch("/check/username", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify({ username: SignupName.value }),
            })
                .then((res) => res.json()) // parse JSON
                .then((data) => {
                    if (data.exists) {
                        // fixed typo
                        showToast(false, "Username already taken");
                        SignupName.style.borderColor = "var(--error)";
                        SignupName.style.color = "var(--error)";
                    } else {
                        showToast(true, "Username is available");
                        SignupName.style.borderColor = "green";
                        SignupName.style.color = "green";
                    }
                })
                .catch((err) => console.log(err));
        });

        signupForm.addEventListener("submit", async (e) => {
            e.preventDefault();

            const name = document.getElementById("signupName").value;
            const email = document.getElementById("signupEmail").value;
            const password = document.getElementById("signupPassword").value;
            const confirmPassword = document.getElementById("confirmPassword").value;
            const agreeTerms = document.getElementById("agreeTerms").checked;

            // Clear previous errors
            hideError("signupNameError");
            hideError("signupEmailError");
            hideError("signupPasswordError");
            hideError("confirmPasswordError");

            // Validate inputs
            let hasError = false;

            if (!name || name.trim().length < 5) {
                showError("signupNameError", "Name must be at least 5 characters long");
                hasError = true;
            }

            if (!email) {
                showError("signupEmailError", "Email is required");
                hasError = true;
            } else if (!validateEmail(email)) {
                showError("signupEmailError", "Please enter a valid email address");
                hasError = true;
            }

            if (!password) {
                showError("signupPasswordError", "Password is required");
                hasError = true;
            } else if (!validatePassword(password)) {
                showError("signupPasswordError", "Password must be at least 8 characters long");
                hasError = true;
            }

            if (!confirmPassword) {
                showError("confirmPasswordError", "Please confirm your password");
                hasError = true;
            } else if (password !== confirmPassword) {
                showError("confirmPasswordError", "Passwords do not match");
                hasError = true;
            }

            if (!agreeTerms) {
                showToast(false, "Please agree to the Terms of Service and Privacy Policy");
                hasError = true;
            }

            if (hasError) return;

            const submitBtn = e.target.querySelector('button[type="submit"]');
            setLoading(submitBtn, true);

            try {
                const res = await fetch("/auth/signup", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ username: name, email, password }),
                });

                const data = await res.json();

                if (res.status !== 200) {
                    showToast(false, data.message || "Signup failed");
                } else {
                    showToast(true, data.message);
                    hideModal(signupModal);
                    signupForm.reset();
                    // Optionally store token: localStorage.setItem("token", data.token);
                }
            } catch (error) {
                showToast(false, "Failed to create account. Please try again.");
                console.log(error);
            } finally {
                setLoading(submitBtn, false);
            }
        });


        // Google Login
        googleLoginBtn.addEventListener("click", async () => {
            setLoading(googleLoginBtn, true);

            try {
                // Simulate Google OAuth process
                window.location.href = "/auth/google";

                // In a real app, you would integrate with Google OAuth API
                // showToast(true, "Google login successful! Welcome.");

                setTimeout(() => {
                    console.log("Redirecting to dashboard...");
                }, 1500);
            } catch (error) {
                showToast(false, "Google login failed. Please try again.");
            } finally {
                setLoading(googleLoginBtn, false);
            }
        });

        // Remember me functionality
        document.getElementById("rememberMe").addEventListener("change", (e) => {
            const isChecked = e.target.checked;
            localStorage.setItem("rememberMe", isChecked);

            if (isChecked) {
                showToast(true, "Login credentials will be remembered");
            }
        });

        // Load saved preference
        document.addEventListener("DOMContentLoaded", () => {
            const rememberMe = localStorage.getItem("rememberMe") === "true";
            document.getElementById("rememberMe").checked = rememberMe;
        });

        // Add some interactive animations
        document.addEventListener("DOMContentLoaded", () => {
            // Add hover effects to form inputs
            const inputs = document.querySelectorAll("input");
            inputs.forEach((input) => {
                input.addEventListener("focus", () => {
                    input.parentElement.style.transform = "translateY(-1px)";
                });

                input.addEventListener("blur", () => {
                    input.parentElement.style.transform = "translateY(0)";
                });
            });

            // Add ripple effect to buttons
            const buttons = document.querySelectorAll("button");
            buttons.forEach((button) => {
                button.addEventListener("click", function (e) {
                    const ripple = document.createElement("span");
                    const rect = this.getBoundingClientRect();
                    const size = Math.max(rect.width, rect.height);
                    const x = e.clientX - rect.left - size / 2;
                    const y = e.clientY - rect.top - size / 2;

                    ripple.style.width = ripple.style.height = size + "px";
                    ripple.style.left = x + "px";
                    ripple.style.top = y + "px";
                    ripple.classList.add("ripple");

                    // Ensure ripple is removed if it already exists to prevent build-up
                    const existingRipple = this.querySelector(".ripple");
                    if (existingRipple) {
                        existingRipple.remove();
                    }

                    this.appendChild(ripple);

                    setTimeout(() => {
                        ripple.remove();
                    }, 600);
                });
            });
        });

        /* Changed: Removed the commented-out style injection from here, as it's now in the main <style> tag. */

  
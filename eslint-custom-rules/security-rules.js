/**
 * Custom ESLint Security Rules for FashioNexus Backend
 * These rules detect specific security vulnerabilities in the application
 */

export default {
  rules: {
    // Rule 1: Detect missing authentication on critical routes
    "detect-missing-authentication": {
      meta: {
        type: "problem",
        docs: {
          description: "Detect routes without authentication middleware",
          category: "Security",
          recommended: true
        },
        messages: {
          missingAuth: "Critical route '{{ method }} {{ path }}' is missing authentication middleware. This could allow unauthorized access.",
          suspiciousRoute: "Route '{{ method }} {{ path }}' may need authentication verification."
        },
        schema: []
      },
      create(context) {
        const criticalMethods = ['delete', 'put', 'post', 'patch'];
        const criticalPaths = ['/delete', '/update', '/add', '/create', '/status'];
        
        return {
          CallExpression(node) {
            // Check for router.METHOD() calls
            if (
              node.callee.type === 'MemberExpression' &&
              node.callee.object.name === 'router' &&
              criticalMethods.includes(node.callee.property.name)
            ) {
              const method = node.callee.property.name;
              const args = node.arguments;
              
              if (args.length >= 1) {
                const pathArg = args[0];
                let path = '';
                
                if (pathArg.type === 'Literal') {
                  path = pathArg.value;
                }
                
                // Check if route is critical and lacks authentication middleware
                const hasCriticalPath = criticalPaths.some(cp => path.includes(cp));
                const hasAuthMiddleware = args.length > 2 || 
                  (args.length === 2 && args[1].type === 'Identifier' && 
                   args[1].name.toLowerCase().includes('verif'));
                
                if ((hasCriticalPath || method === 'delete' || path.includes('all')) && !hasAuthMiddleware) {
                  context.report({
                    node,
                    messageId: 'missingAuth',
                    data: {
                      method: method.toUpperCase(),
                      path: path
                    }
                  });
                }
              }
            }
          }
        };
      }
    },

    // Rule 2: Detect sensitive data exposure
    "detect-sensitive-data-exposure": {
      meta: {
        type: "problem",
        docs: {
          description: "Detect sensitive data being logged or exposed",
          category: "Security",
          recommended: true
        },
        messages: {
          sensitiveLog: "Sensitive data '{{ data }}' is being logged. This could expose passwords, tokens, or personal information.",
          sensitiveResponse: "Potentially sending sensitive data in response without sanitization.",
          credentialsInCode: "Hardcoded credentials detected: '{{ credential }}'. Use environment variables instead."
        },
        schema: []
      },
      create(context) {
        const sensitiveKeywords = ['password', 'token', 'secret', 'otp', 'jwt', 'auth', 'credential', 'pass'];
        const credentialPatterns = ['@gmail.com', 'mongodb+srv://', 'pass:', 'password:'];
        
        return {
          // Detect console.log with sensitive data
          CallExpression(node) {
            if (
              node.callee.type === 'MemberExpression' &&
              node.callee.object.name === 'console' &&
              node.callee.property.name === 'log'
            ) {
              const args = node.arguments;
              args.forEach(arg => {
                const sourceCode = context.getSourceCode().getText(arg);
                const lowerSource = sourceCode.toLowerCase();
                
                if (sensitiveKeywords.some(keyword => lowerSource.includes(keyword))) {
                  context.report({
                    node,
                    messageId: 'sensitiveLog',
                    data: { data: sourceCode }
                  });
                }
              });
            }

            // Detect res.json() without password removal
            if (
              node.callee.type === 'MemberExpression' &&
              node.callee.property.name === 'json'
            ) {
              const args = node.arguments;
              if (args.length > 0 && args[0].type === 'Identifier') {
                const sourceCode = context.getSourceCode().getText(args[0]);
                if (!sourceCode.includes('...rest') && !sourceCode.includes('password:')) {
                  // Check if we're in a route handler context
                  const scope = context.getScope();
                  const inRouteHandler = scope.variables.some(v => 
                    v.name === 'validUser' || v.name === 'user' || v.name === 'users'
                  );
                  
                  if (inRouteHandler) {
                    context.report({
                      node,
                      messageId: 'sensitiveResponse'
                    });
                  }
                }
              }
            }
          },

          // Detect hardcoded credentials
          Literal(node) {
            if (typeof node.value === 'string') {
              credentialPatterns.forEach(pattern => {
                if (node.value.includes(pattern)) {
                  context.report({
                    node,
                    messageId: 'credentialsInCode',
                    data: { credential: pattern }
                  });
                }
              });
            }
          }
        };
      }
    },

    // Rule 3: Detect NoSQL injection vulnerabilities
    "detect-nosql-injection": {
      meta: {
        type: "problem",
        docs: {
          description: "Detect potential NoSQL injection vulnerabilities",
          category: "Security",
          recommended: true
        },
        messages: {
          unsafeQuery: "Unsafe MongoDB query using user input '{{ input }}'. This could lead to NoSQL injection.",
          objectInjection: "Direct object access from user input '{{ property }}' without validation. Risk of NoSQL injection.",
          regexInjection: "Using regex with unvalidated user input '{{ input }}'. This could lead to ReDoS or injection attacks."
        },
        schema: []
      },
      create(context) {
        return {
          CallExpression(node) {
            // Detect Model.findOne(), Model.find() with user input
            if (
              node.callee.type === 'MemberExpression' &&
              ['findOne', 'find', 'findById', 'findByIdAndUpdate', 'findByIdAndDelete', 'findOneAndDelete'].includes(node.callee.property.name)
            ) {
              const args = node.arguments;
              if (args.length > 0) {
                const queryArg = args[0];
                const sourceCode = context.getSourceCode().getText(queryArg);
                
                // Check for direct req.body, req.query, req.params usage
                if (sourceCode.includes('req.body') || 
                    sourceCode.includes('req.query') || 
                    sourceCode.includes('req.params')) {
                  context.report({
                    node,
                    messageId: 'unsafeQuery',
                    data: { input: sourceCode }
                  });
                }

                // Check for regex with user input
                if (queryArg.type === 'ObjectExpression') {
                  queryArg.properties.forEach(prop => {
                    if (prop.value && prop.value.type === 'ObjectExpression') {
                      prop.value.properties.forEach(innerProp => {
                        if (innerProp.key && innerProp.key.name === '$regex') {
                          const regexSource = context.getSourceCode().getText(innerProp.value);
                          if (regexSource.includes('req.')) {
                            context.report({
                              node: innerProp,
                              messageId: 'regexInjection',
                              data: { input: regexSource }
                            });
                          }
                        }
                      });
                    }
                  });
                }
              }
            }

            // Detect parseInt without validation
            if (
              node.callee.name === 'parseInt' &&
              node.arguments.length > 0
            ) {
              const arg = context.getSourceCode().getText(node.arguments[0]);
              if (arg.includes('req.query') || arg.includes('req.params')) {
                context.report({
                  node,
                  messageId: 'objectInjection',
                  data: { property: arg }
                });
              }
            }
          }
        };
      }
    },

    // Rule 4: Detect insecure OTP implementation
    "detect-insecure-otp": {
      meta: {
        type: "problem",
        docs: {
          description: "Detect insecure OTP implementation",
          category: "Security",
          recommended: true
        },
        messages: {
          insecureStorage: "OTP stored in-memory using '{{ storage }}'. This is not persistent and insecure for production.",
          noExpiration: "OTP has no expiration time. Implement time-based expiration for security.",
          weakOtp: "OTP generation uses Math.random() which is predictable. Use crypto.randomBytes() instead.",
          noRateLimit: "OTP endpoint '{{ endpoint }}' has no rate limiting. This allows brute force attacks."
        },
        schema: []
      },
      create(context) {
        let hasRateLimit = false;
        
        return {
          // Detect Map() storage for OTP
          NewExpression(node) {
            if (node.callee.name === 'Map') {
              const parent = context.getAncestors();
              const varDecl = parent.find(p => p.type === 'VariableDeclarator');
              if (varDecl && varDecl.id.name.toLowerCase().includes('otp')) {
                context.report({
                  node,
                  messageId: 'insecureStorage',
                  data: { storage: 'Map()' }
                });
              }
            }
          },

          // Detect Math.random() in OTP generation
          CallExpression(node) {
            if (
              node.callee.type === 'MemberExpression' &&
              node.callee.object.name === 'Math' &&
              node.callee.property.name === 'random'
            ) {
              // Check if in OTP context
              const ancestors = context.getAncestors();
              const inOtpFunction = ancestors.some(ancestor => 
                ancestor.type === 'FunctionDeclaration' && 
                ancestor.id && 
                ancestor.id.name.toLowerCase().includes('otp')
              );
              
              if (inOtpFunction) {
                context.report({
                  node,
                  messageId: 'weakOtp'
                });
              }
            }

            // Detect OTP routes without rate limiting
            if (
              node.callee.type === 'MemberExpression' &&
              node.callee.object.name === 'app' &&
              node.callee.property.name === 'post'
            ) {
              const pathArg = node.arguments[0];
              if (pathArg && pathArg.type === 'Literal') {
                const path = pathArg.value;
                if (path.includes('otp') || path.includes('sendotp') || path.includes('verifyotp')) {
                  // Check if there's rate limiting middleware
                  const hasMiddleware = node.arguments.length > 2;
                  if (!hasMiddleware) {
                    context.report({
                      node,
                      messageId: 'noRateLimit',
                      data: { endpoint: path }
                    });
                  }
                }
              }
            }

            // Detect OTP set without expiration
            if (
              node.callee.type === 'MemberExpression' &&
              node.callee.property.name === 'set' &&
              node.callee.object.name && 
              node.callee.object.name.toLowerCase().includes('otp')
            ) {
              // OTP stored without timestamp or expiration
              if (node.arguments.length === 2) {
                context.report({
                  node,
                  messageId: 'noExpiration'
                });
              }
            }
          }
        };
      }
    },

    // Rule 5: Detect XSS vulnerabilities
    "detect-xss-vulnerabilities": {
      meta: {
        type: "problem",
        docs: {
          description: "Detect potential XSS vulnerabilities",
          category: "Security",
          recommended: true
        },
        messages: {
          unsanitizedInput: "User input '{{ input }}' used without sanitization. This could lead to XSS attacks.",
          dangerousHtml: "HTML content sent without sanitization in '{{ context }}'. Risk of XSS.",
          noContentType: "Response missing Content-Type header. Could lead to XSS in some contexts."
        },
        schema: []
      },
      create(context) {
        return {
          // Detect email sending with HTML
          CallExpression(node) {
            if (
              node.callee.type === 'MemberExpression' &&
              node.callee.property.name === 'sendMail'
            ) {
              const args = node.arguments;
              if (args.length > 0 && args[0].type === 'ObjectExpression') {
                const htmlProp = args[0].properties.find(p => 
                  p.key && p.key.name === 'html'
                );
                if (htmlProp) {
                  const htmlValue = context.getSourceCode().getText(htmlProp.value);
                  if (htmlValue.includes('${') && htmlValue.includes('req.')) {
                    context.report({
                      node: htmlProp,
                      messageId: 'dangerousHtml',
                      data: { context: 'email HTML' }
                    });
                  }
                }
              }
            }

            // Detect res.json() with unsanitized user input
            if (
              node.callee.type === 'MemberExpression' &&
              node.callee.property.name === 'json' &&
              node.arguments.length > 0
            ) {
              const arg = node.arguments[0];
              if (arg.type === 'ObjectExpression') {
                arg.properties.forEach(prop => {
                  if (prop.value) {
                    const valueSource = context.getSourceCode().getText(prop.value);
                    if (valueSource.includes('req.body') || valueSource.includes('req.query')) {
                      context.report({
                        node: prop,
                        messageId: 'unsanitizedInput',
                        data: { input: valueSource }
                      });
                    }
                  }
                });
              }
            }
          }
        };
      }
    },

    // Rule 6: Detect insecure file upload
    "detect-insecure-file-upload": {
      meta: {
        type: "problem",
        docs: {
          description: "Detect insecure file upload implementations",
          category: "Security",
          recommended: true
        },
        messages: {
          noFileValidation: "File upload at '{{ route }}' has no file type validation. This allows uploading of malicious files.",
          noSizeLimit: "File upload has no size limit configured. This could lead to DoS attacks.",
          insecureFilename: "File upload uses unsanitized filename. This could lead to path traversal attacks.",
          noVirusScan: "File upload has no virus scanning. Uploaded files could contain malware."
        },
        schema: []
      },
      create(context) {
        return {
          CallExpression(node) {
            // Detect multer() configuration
            if (node.callee.name === 'multer') {
              const arg = node.arguments[0];
              let hasLimits = false;
              let hasFileFilter = false;
              
              if (arg && arg.type === 'ObjectExpression') {
                arg.properties.forEach(prop => {
                  if (prop.key.name === 'limits') hasLimits = true;
                  if (prop.key.name === 'fileFilter') hasFileFilter = true;
                });
              }
              
              if (!hasLimits) {
                context.report({
                  node,
                  messageId: 'noSizeLimit'
                });
              }
              
              if (!hasFileFilter) {
                context.report({
                  node,
                  messageId: 'noFileValidation',
                  data: { route: 'multer configuration' }
                });
              }
            }

            // Detect upload.array() or upload.single() in routes
            if (
              node.callee.type === 'MemberExpression' &&
              (node.callee.property.name === 'array' || node.callee.property.name === 'single') &&
              node.callee.object.name === 'upload'
            ) {
              // Check if there's validation after upload
              const parent = context.getAncestors().slice(-1)[0];
              context.report({
                node,
                messageId: 'noVirusScan'
              });
            }

            // Detect Date.now() + extname pattern (insecure filename)
            if (
              node.callee.type === 'MemberExpression' &&
              node.callee.object.name === 'Date' &&
              node.callee.property.name === 'now'
            ) {
              const parent = context.getAncestors();
              const inCallback = parent.some(p => 
                p.type === 'Property' && p.key && p.key.name === 'filename'
              );
              
              if (inCallback) {
                context.report({
                  node,
                  messageId: 'insecureFilename'
                });
              }
            }
          }
        };
      }
    },

    // Rule 7: Detect missing security headers
    "detect-missing-security-headers": {
      meta: {
        type: "problem",
        docs: {
          description: "Detect missing security headers",
          category: "Security",
          recommended: true
        },
        messages: {
          noHelmet: "Application is not using helmet middleware. This leaves the app vulnerable to various attacks.",
          insecureCors: "CORS configured with 'origin: \"*\"'. This allows any domain to access your API.",
          noRateLimiting: "No rate limiting detected. Application is vulnerable to brute force and DoS attacks.",
          noCsp: "No Content Security Policy detected. This increases XSS risk."
        },
        schema: []
      },
      create(context) {
        let hasHelmet = false;
        let hasRateLimit = false;
        
        return {
          Program(node) {
            // Check imports for helmet and rate limiting
            node.body.forEach(statement => {
              if (statement.type === 'ImportDeclaration') {
                const source = statement.source.value;
                if (source === 'helmet') hasHelmet = true;
                if (source === 'express-rate-limit') hasRateLimit = true;
              }
            });
          },
          
          CallExpression(node) {
            // Detect CORS with wildcard
            if (node.callee.name === 'cors' && node.arguments.length > 0) {
              const arg = node.arguments[0];
              if (arg.type === 'ObjectExpression') {
                const originProp = arg.properties.find(p => 
                  p.key && p.key.name === 'origin'
                );
                if (originProp && originProp.value.type === 'Literal' && 
                    originProp.value.value === '*') {
                  context.report({
                    node: originProp,
                    messageId: 'insecureCors'
                  });
                }
              }
            }
          },
          
          'Program:exit'() {
            if (!hasHelmet) {
              context.report({
                loc: { line: 1, column: 0 },
                messageId: 'noHelmet'
              });
            }
            if (!hasRateLimit) {
              context.report({
                loc: { line: 1, column: 0 },
                messageId: 'noRateLimiting'
              });
            }
          }
        };
      }
    },

    // Rule 8: Detect missing CSRF protection
    "detect-missing-csrf": {
      meta: {
        type: "problem",
        docs: {
          description: "Detect missing CSRF protection in cookie-based authentication",
          category: "Security",
          recommended: true
        },
        messages: {
          noCsrfProtection: "Application uses cookie-based authentication but has no CSRF protection. This makes it vulnerable to CSRF attacks.",
          insecureCookie: "Cookie '{{ cookie }}' set without 'sameSite' or 'secure' flags. This increases CSRF risk.",
          missingCsrfToken: "State-changing endpoint '{{ method }} {{ path }}' has no CSRF token verification."
        },
        schema: []
      },
      create(context) {
        let usesCookies = false;
        let hasCsrfProtection = false;
        
        return {
          Program(node) {
            // Check for CSRF middleware import
            node.body.forEach(statement => {
              if (statement.type === 'ImportDeclaration') {
                const source = statement.source.value;
                if (source === 'csurf' || source === 'csrf') {
                  hasCsrfProtection = true;
                }
              }
            });
          },
          
          CallExpression(node) {
            // Detect cookie() calls
            if (
              node.callee.type === 'MemberExpression' &&
              node.callee.property.name === 'cookie'
            ) {
              usesCookies = true;
              
              const args = node.arguments;
              if (args.length >= 2) {
                const cookieName = args[0].type === 'Literal' ? args[0].value : 'unknown';
                let hasSecureFlags = false;
                
                if (args.length > 2 && args[2].type === 'ObjectExpression') {
                  const sameSiteProp = args[2].properties.find(p => 
                    p.key && p.key.name === 'sameSite'
                  );
                  const secureProp = args[2].properties.find(p => 
                    p.key && p.key.name === 'secure'
                  );
                  
                  hasSecureFlags = sameSiteProp && secureProp;
                }
                
                if (!hasSecureFlags) {
                  context.report({
                    node,
                    messageId: 'insecureCookie',
                    data: { cookie: cookieName }
                  });
                }
              }
            }

            // Detect state-changing routes
            if (
              node.callee.type === 'MemberExpression' &&
              ['post', 'put', 'delete', 'patch'].includes(node.callee.property.name) &&
              (node.callee.object.name === 'app' || node.callee.object.name === 'router')
            ) {
              const method = node.callee.property.name;
              const pathArg = node.arguments[0];
              const path = pathArg && pathArg.type === 'Literal' ? pathArg.value : 'unknown';
              
              // Check if route has CSRF middleware
              const hasMiddleware = node.arguments.length > 2 || 
                (node.arguments.length === 2 && node.arguments[1].type === 'Identifier' &&
                 node.arguments[1].name.toLowerCase().includes('csrf'));
              
              if (!hasMiddleware && !hasCsrfProtection) {
                context.report({
                  node,
                  messageId: 'missingCsrfToken',
                  data: {
                    method: method.toUpperCase(),
                    path: path
                  }
                });
              }
            }
          },
          
          'Program:exit'() {
            if (usesCookies && !hasCsrfProtection) {
              context.report({
                loc: { line: 1, column: 0 },
                messageId: 'noCsrfProtection'
              });
            }
          }
        };
      }
    }
  }
};

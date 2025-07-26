var express = require('express');
var mysql = require('mysql');
var bcrypt = require('bcrypt');
var session = require('express-session');
var nodemailer = require('nodemailer');
var app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));

// Setup session
app.use(session({
    secret: "39e06539d8119df213b96c1540e80467b47a98eff9d89f17d7f8d60eb49abeee",
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false,httpOnly: true }
}));

// MySQL Connection
var con = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "root",
    database: "mydb46"
});

con.connect(function(err) {
    if (err) {
        console.error("Database connection failed: " + err.stack);
        return;
    }
    console.log("Connected to database");
});

// Middleware to protect pages
function requireLogin(req, res, next) {
  if (req.session && req.session.user) {
    next(); // ✅ User is logged in, proceed!
  } else {
    res.redirect('/login.html'); // ❌ Not logged in, redirect to login
  }
}



// Session Check for Navbar Update

app.get('/session-check', (req, res) => {
  if (req.session.user) {
    return res.json({ loggedIn: true, user: req.session.user });
  }
  res.json({ loggedIn: false });
});


// Serve HTML Pages (Protect Home Page)
app.get('/', requireLogin, (req, res) => res.sendFile(__dirname + '/home.html'));
app.get('/list_elections', requireLogin, (req, res) => res.sendFile(__dirname + '/list_elections.html'));
app.get('/login', (req, res) => res.sendFile(__dirname + '/login.html'));
app.get('/password_reset',requireLogin, (req, res) => res.sendFile(__dirname + '/password_reset.html'));
app.get('/reset_password_form',requireLogin, (req, res) => {
    res.sendFile(__dirname + '/reset_password_form.html');
});
app.get('/verify_voter',requireLogin, (req, res) => {
    res.sendFile(__dirname + '/verify_voter.html');
  });
  

app.get('/register', (req, res) => res.sendFile(__dirname + '/register.html'));
app.get('/results', requireLogin, (req, res) => res.sendFile(__dirname + '/results.html'));
app.get('/vote', requireLogin, (req, res) => res.sendFile(__dirname + '/vote.html'));



// Password Reset Request (POST)
const crypto = require('crypto'); // To generate tokens

// Send password reset email
app.post('/password_reset', (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).send('Email is required');
  }

  const sql = "SELECT * FROM users WHERE email = ?";
  con.query(sql, [email], (err, results) => {
    if (err) {
      console.error('DB error:', err);
      return res.status(500).send('Server error');
    }

    if (results.length === 0) {
      return res.status(404).send('No user found with this email');
    }

    // Generate a token (for example)
    const token = crypto.randomBytes(20).toString('hex');

    // Save token to DB (you should have a reset_token and expire field in users table)
    const updateSql = "UPDATE users SET reset_token = ?, reset_token_expire = DATE_ADD(NOW(), INTERVAL 1 HOUR) WHERE email = ?";
    con.query(updateSql, [token, email], (err) => {
      if (err) {
        console.error('DB error:', err);
        return res.status(500).send('Server error');
      }

      // Send reset link to user
      const resetLink = `http://localhost:8688/reset_password_form?token=${token}`;

      const mailOptions = {
        from: 'admin@onlinevoting.com',
        to: email,
        subject: 'Password Reset',
        text: `Click this link to reset your password: ${resetLink}`
      };

      transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
          console.error('Error sending email:', error);
          return res.status(500).send('Failed to send reset email');
        }

        res.send('Password reset link has been sent to your email');
      });
    });
  });
});


// Handle Registration with Email Verification
app.post('/register', async (req, res) => {
    var { username, email, password, confirm_password, college_id } = req.body;
    if (password !== confirm_password) {
        return res.send("Error: Passwords do not match.");
    }
    try {
        var hashedPassword = await bcrypt.hash(password, 10);
        var sql = "INSERT INTO users (username, email, password, college_id, is_verified) VALUES (?, ?, ?, ?, 0)";
        con.query(sql, [username, email, hashedPassword, college_id], function(err, result) {
            if (err) return res.status(500).send("Error: Registration failed. " + err.message);
            sendVerificationEmail(email);
            res.send("Registration successful! Please check your email for verification.");
        });
    } catch (error) {
        res.status(500).send("Error: Something went wrong.");
    }
});


const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 587,                 // ✅ Use port 587 for TLS
  secure: false,             // ✅ Must be false for port 587
  auth: {
    user: 'thotakoushik69@gmail.com',        // ✅ Your Gmail address
    pass: 'jory ksjd ancr rvxu'            // ✅ App Password, NOT your Gmail password
  },
  tls: {
    rejectUnauthorized: false            // ✅ Allow self-signed certs if needed
  }
});



function sendVerificationEmail(email) {
    var verificationLink = `http://localhost:8688/verify?email=${email}`;
    var mailOptions = {
        from: 'admin@onlinevoting.com',
        to: email,
        subject: 'Email Verification',
        text: `Click the link to verify your email: ${verificationLink}`
    };
    transporter.sendMail(mailOptions, function(error) {
        if (error) console.log("Error sending email: " + error);
    });
}

app.get('/verify', (req, res) => {
    var email = req.query.email;
    var sql = "UPDATE users SET is_verified = 1 WHERE email = ?";
    
    con.query(sql, [email], function(err, result) {
        if (err) {
            return res.send("Error verifying email.");
        }
        res.send("Email verified successfully! <a href='/login'>Login here</a>");
    });
});


// ✅ KEEP THIS ADMIN+USER LOGIN HANDLER (Line ~155 in original)
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  // ✅ Check admin table first
  const adminSql = "SELECT * FROM admins WHERE username = ?";
  con.query(adminSql, [username], (err, adminResults) => {
    if (err) return res.status(500).json({ success: false, message: "Database error." });

    if (adminResults.length > 0) {
      const admin = adminResults[0];
      if (password === admin.password) {
        req.session.user = {
          id: admin.id,
          username: admin.username,
          isAdmin: true
        };
        return req.session.save(() => {
          res.json({ success: true, message: "Admin login successful!", isAdmin: true });
        });
      } else {
        return res.json({ success: false, message: "Invalid admin password." });
      }
    }

    // ✅ Not admin? Check regular user
    const userSql = "SELECT * FROM users WHERE username = ?";
    con.query(userSql, [username], (err, userResults) => {
      if (err) return res.status(500).json({ success: false, message: "Database error." });
      if (userResults.length === 0) return res.json({ success: false, message: "Invalid username or password." });

      const user = userResults[0];
      bcrypt.compare(password, user.password, (err, isMatch) => {
        if (err || !isMatch) return res.json({ success: false, message: "Invalid username or password." });

        req.session.user = {
          id: user.id,
          username: user.username,
          email: user.email,
          isAdmin: false
        };
        req.session.save(() => {
          res.json({ success: true, message: "Login successful!", isAdmin: false });
        });
      });
    });
  });
});

// 🚫 DELETE THIS DUPLICATE LOGIN ROUTE (Found at line ~284 in original)
// app.post('/login', (req, res) => { ... });


app.post('/update_password', (req, res) => {
    const { token, password, confirm_password } = req.body;
  
    if (!token || !password || !confirm_password) {
      return res.status(400).send('All fields are required');
    }
  
    if (password !== confirm_password) {
      return res.status(400).send('Passwords do not match');
    }
  
    // Find user with token and check expiry
    const sql = "SELECT * FROM users WHERE reset_token = ? AND reset_token_expire > NOW()";
    con.query(sql, [token], async (err, results) => {
      if (err) {
        console.error('DB error:', err);
        return res.status(500).send('Server error');
      }
  
      if (results.length === 0) {
        return res.status(400).send('Invalid or expired token');
      }
  
      const hashedPassword = await bcrypt.hash(password, 10);
  
      // Update password and clear token
      const updateSql = "UPDATE users SET password = ?, reset_token = NULL, reset_token_expire = NULL WHERE reset_token = ?";
      con.query(updateSql, [hashedPassword, token], (err) => {
        if (err) {
          console.error('DB error:', err);
          return res.status(500).send('Failed to update password');
        }
  
        res.send('Password updated successfully! <a href="/login.html">Login here</a>');
      });
    });
  });


  app.post('/verify_voter', (req, res) => {
    const { college_id, email } = req.body;
  
    if (!college_id || !email) {
      return res.status(400).json({ success: false, message: 'Both College ID and Email are required.' });
    }
  
    const sql = "SELECT * FROM users WHERE college_id = ? AND email = ?";
    con.query(sql, [college_id, email], (err, results) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ success: false, message: 'Server error. Please try again.' });
      }
  
      if (results.length === 0) {
        return res.json({ success: false, message: 'Invalid College ID or Email.' });
      }
  
      // ✅ Verification successful!
      req.session.user = {
        id: results[0].id,
        username: results[0].username,
        college_id: results[0].college_id,
        email: results[0].email
      };
  
      return res.json({ success: true });
    });
  });
  
  

app.get('/user_elections', requireLogin, (req, res) => {
    const sql = "SELECT id, title FROM elections";
    con.query(sql, (err, results) => {
        if (err) {
            console.error('Error fetching elections:', err);
            return res.status(500).send('Failed to fetch elections.');
        }
        res.json(results);
    });
});


app.get('/candidates', requireLogin, (req, res) => {
    const { election_id } = req.query;
    if (!election_id) return res.status(400).send('Election ID required.');

    const sql = "SELECT * FROM candidates WHERE election_id = ?";
    con.query(sql, [election_id], (err, results) => {
        if (err) {
            console.error('Error fetching candidates:', err);
            return res.status(500).send('Failed to fetch candidates.');
        }

        res.json(results);
    });
});



// Admin Role Management
app.get('/admin', (req, res) => {
  if (!req.session.user || !req.session.user.isAdmin) {
    return res.status(403).send('Access Denied');
  }

  res.sendFile(__dirname + '/admin.html');
});






// Get elections for dropdown in admin.html
app.get('/elections', requireLogin, (req, res) => {
  // ✅ Check if user is logged in
  if (!req.session.user) {
      return res.status(401).json({ error: 'Unauthorized. Please log in.' });
  }

  // ✅ Check if user is admin
  if (!req.session.user.isAdmin) {
      return res.status(403).json({ error: 'Access Denied. Admins only.' });
  }

  // ✅ Fetch Elections
  const sql = "SELECT id, title, end_time FROM elections";
  con.query(sql, (err, results) => {
      if (err) {
          console.error('Database error:', err);
          return res.status(500).json({ error: 'Database error' });
      }

      res.json(results); // ✅ Return JSON response
  });
});

// Add candidate to election
// Add election with start & end time
app.post('/add_election', requireLogin, (req, res) => {
  if (!req.session.user.isAdmin) {
      return res.status(403).send("Access Denied: You are not an admin.");
  }

  const { election_name, start_time, end_time } = req.body;

  if (!election_name || !start_time || !end_time) {
      return res.status(400).send("All fields are required.");
  }

  const sql = "INSERT INTO elections (title, start_time, end_time) VALUES (?, ?, ?)";
  con.query(sql, [election_name, start_time, end_time], (err, result) => {
      if (err) {
          console.error("Error adding election:", err);
          return res.status(500).send("Database error: Failed to add election.");
      }

      console.log(`Election "${election_name}" added successfully!`);
      res.send("Election added successfully!");
  });
});


// Auto-delete expired elections and candidates
function deleteExpiredElections() {
  const deleteSql = `
      DELETE e, c FROM elections e
      LEFT JOIN candidates c ON e.id = c.election_id
      WHERE e.end_time < NOW()
  `;
  con.query(deleteSql, (err, result) => {
      if (err) {
          console.error('Error deleting expired elections:', err);
      } else {
          console.log('Expired elections and candidates deleted:', result.affectedRows);
      }
  });
}

// Schedule deletion every hour
setInterval(deleteExpiredElections, 60 * 60 * 1000); // Runs every 1 hour


  

app.post('/add_candidate', requireLogin, (req, res) => {
    if (!req.session.user.isAdmin) {
        return res.status(403).send('Access Denied');
    }

    const { election_id, candidate_name } = req.body;

    // 🔹 Check if the candidate already exists in this election
    const checkSql = "SELECT * FROM candidates WHERE election_id = ? AND candidate_name = ?";
    con.query(checkSql, [election_id, candidate_name], (err, results) => {
        if (err) {
            console.error('Error checking for existing candidate:', err);
            return res.status(500).send('Failed to check for existing candidate.');
        }

        if (results.length > 0) {
            return res.status(400).send('Candidate already exists in this election!');
        }

        // 🔹 If no duplicate, insert the candidate
        const insertSql = "INSERT INTO candidates (election_id, candidate_name) VALUES (?, ?)";
        con.query(insertSql, [election_id, candidate_name], (err, result) => {
            if (err) {
                console.error('Error adding candidate:', err);
                return res.status(500).send('Failed to add candidate.');
            }

            res.send('Candidate added successfully!');
        });
    });
});


// 🔹 Voting API (Ensure One Vote Per User)
app.post('/vote', requireLogin, (req, res) => {
  const { election_id, candidate_id } = req.body;
  const userId = req.session.user.id;

  // ✅ Check if election is still active
  const checkElectionSql = `SELECT start_time, end_time FROM elections WHERE id = ?`;
  con.query(checkElectionSql, [election_id], (err, results) => {
    if (err) {
      console.error('❌ Database error:', err);
      return res.status(500).json({ success: false, message: '❌ Error checking election status.' });
    }

    if (results.length === 0) {
      return res.status(400).json({ success: false, message: '❌ Invalid Election ID.' });
    }

    const { start_time, end_time } = results[0];
    const now = new Date();

    if (now < new Date(start_time)) {
      return res.status(400).json({ success: false, message: '❌ Voting has not started yet.' });
    }

    if (now > new Date(end_time)) {
      return res.status(400).json({ success: false, message: '❌ Voting has ended.' });
    }

    // ✅ Check if the user has already voted
    const checkVoteSql = "SELECT * FROM votes WHERE user_id = ? AND election_id = ?";
    con.query(checkVoteSql, [userId, election_id], (err, results) => {
      if (err) {
        console.error('❌ Database error:', err);
        return res.status(500).json({ success: false, message: '❌ Error checking previous vote.' });
      }

      if (results.length > 0) {
        return res.status(400).json({ success: false, message: '❌ You have already voted in this election.' });
      }

      // ✅ Insert the vote into the database
      const insertVoteSql = "INSERT INTO votes (user_id, election_id, candidate_id) VALUES (?, ?, ?)";
      con.query(insertVoteSql, [userId, election_id, candidate_id], (err) => {
        if (err) {
          console.error('❌ Database error:', err);
          return res.status(500).json({ success: false, message: '❌ Error submitting vote.' });
        }

        console.log('✅ Vote recorded successfully.');

        // ✅ Send confirmation email
        const voterEmail = req.session.user.email;
        const userName = req.session.user.username;

        const mailOptions = {
          from: 'admin@onlinevoting.com',
          to: voterEmail,
          subject: '🗳️ Voting Confirmation - Online Voting System',
          text: `Dear ${userName},

✅ Your vote for Election ID "${election_id}" has been successfully submitted.

If you did not authorize this vote or need assistance, please contact us immediately.

📩 Support Email: admin@onlinevoting.com
📞 Support Phone: +91 9876543210

Thank you for participating in the democratic process!

Best regards,  
🗳️ Online Voting Team`
        };

        transporter.sendMail(mailOptions, (error, info) => {
          if (error) {
            console.error('❌ Error sending confirmation email:', error);
            return res.status(500).json({ success: false, message: '✅ Vote submitted but email confirmation failed.' });
          }

          console.log('✅ Confirmation email sent successfully:', info.response);
          res.status(200).json({ success: true, message: '✅ Vote submitted successfully! Confirmation email sent.' });
        });
      });
    });
  });
});

// Start the Express server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

  

// Vote Counting & Results Calculation
app.get('/api/results', (req, res) => {
  const electionsSql = "SELECT * FROM elections";

  con.query(electionsSql, (err, elections) => {
    if (err) {
      console.error('Error fetching elections:', err);
      return res.status(500).json({ error: 'Error fetching elections.' });
    }

    if (!elections.length) return res.json([]);

    const results = [];
    let processed = 0;

    elections.forEach(election => {
      const candidatesSql = `
        SELECT 
          c.id, 
          c.candidate_name, 
          COUNT(v.id) AS vote_count,
          (SELECT MAX(vote_count) FROM (
            SELECT COUNT(v2.id) AS vote_count
            FROM candidates c2
            LEFT JOIN votes v2 ON c2.id = v2.candidate_id
            WHERE c2.election_id = ?
            GROUP BY c2.id
          ) AS counts) AS max_votes
        FROM candidates c
        LEFT JOIN votes v ON c.id = v.candidate_id
        WHERE c.election_id = ?
        GROUP BY c.id, c.candidate_name
        ORDER BY vote_count DESC
      `;

      con.query(candidatesSql, [election.id, election.id], (err, candidates) => {
        if (err) {
          console.error(`Error fetching candidates for election ${election.id}:`, err);
          return res.status(500).json({ error: 'Error fetching candidates.' });
        }

        // Mark all candidates with max_votes as winners
        candidates.forEach(candidate => {
          candidate.isWinner = (candidate.vote_count === candidate.max_votes);
        });

        results.push({
          id: election.id,
          title: election.title,
          candidates: candidates
        });

        processed++;
        if (processed === elections.length) res.json(results);
      });
    });
  });
});
// Keep this route for serving HTML page
app.get('/results', requireLogin, (req, res) => res.sendFile(__dirname + '/results.html'));
  
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).send("Error logging out.");
        }
        res.redirect('/login');  // Redirect user to login page
    });
});

app.post('/send_otp', (req, res) => {
  const { college_id, email } = req.body;

  // Validate user exists
  const sql = "SELECT * FROM users WHERE college_id = ? AND email = ?";
  con.query(sql, [college_id, email], (err, results) => {
    if (err) {
      console.error(err);
      return res.json({ success: false, message: "Database error." });
    }

    if (results.length === 0) {
      return res.json({ success: false, message: "User not found or email not registered." });
    }

    // Generate OTP
    const otp = Math.floor(100000 + Math.random() * 900000);

    // Store OTP in session (you could store in DB if needed)
    req.session.otp = otp;
    req.session.email = email;
    req.session.college_id = college_id;

    // Send OTP via email
    const mailOptions = {
      from: 'youremail@gmail.com',
      to: email,
      subject: 'Your OTP for Voting Verification',
      text: `Your OTP is: ${otp}`
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error(error);
        return res.json({ success: false, message: "Failed to send OTP email." });
      }

      console.log("OTP sent: " + otp);
      res.json({ success: true, message: "OTP sent to your email." });
    });
  });
});

app.post('/verify_otp', (req, res) => {
  const { otp } = req.body;

  if (!req.session.otp) {
    return res.json({ success: false, message: "OTP not found. Please try again." });
  }

  if (parseInt(otp) === req.session.otp) {
    // OTP verified - clear it from session
    delete req.session.otp;

    // You can set additional session vars if needed:
    req.session.verified = true;

    res.json({ success: true, message: "OTP verified successfully!" });
  } else {
    res.json({ success: false, message: "Invalid OTP. Please try again." });
  }
});

// Delete Election & Related Candidates
// ✅ Delete Election and Associated Candidates
app.delete('/delete_election/:id', requireLogin, (req, res) => {
  if (!req.session.user.isAdmin) {
      return res.status(403).send('Access Denied');
  }

  const electionId = req.params.id;

  // Step 1: Delete candidates linked to the election
  const deleteCandidatesSql = "DELETE FROM candidates WHERE election_id = ?";
  con.query(deleteCandidatesSql, [electionId], (err) => {
      if (err) {
          console.error('Error deleting candidates:', err);
          return res.status(500).send('Failed to delete candidates.');
      }

      // Step 2: Delete the election itself
      const deleteElectionSql = "DELETE FROM elections WHERE id = ?";
      con.query(deleteElectionSql, [electionId], (err) => {
          if (err) {
              console.error('Error deleting election:', err);
              return res.status(500).send('Failed to delete election.');
          }

          res.send('Election and associated candidates deleted successfully.');
      });
  });
});

// ✅ Delete Candidate
app.delete('/delete_candidate/:id', requireLogin, (req, res) => {
  if (!req.session.user.isAdmin) {
      return res.status(403).send('Access Denied');
  }

  const candidateId = req.params.id;
  const deleteCandidateSql = "DELETE FROM candidates WHERE id = ?";

  con.query(deleteCandidateSql, [candidateId], (err) => {
      if (err) {
          console.error('Error deleting candidate:', err);
          return res.status(500).send('Failed to delete candidate.');
      }

      res.send('Candidate deleted successfully.');
  });
});



// Start Server
app.listen(8688, '0.0.0.0', () => {
  console.log('Server is running on port 8688 and accessible at http://192.168.253.230:8688');
});


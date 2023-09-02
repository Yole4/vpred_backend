// server.js
const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const cors = require('cors');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const mime = require('mime-types');
const validator = require('validator');
const sanitizeHtml = require('sanitize-html');
const fs = require('fs');
const nodemailer = require('nodemailer');
const path = require('path');
require('dotenv').config();
const axios = require('axios');
const cheerio = require('cheerio');
const mammoth = require('mammoth');
const PDFParser = require('pdf-parse');
const Docxtemplater = require('docxtemplater');
const JSZip = require('jszip');


// import cookieParser from 'cookie-parser';

const app = express();
const port = 3001;
app.use(express.json());
app.use(cookieParser());

app.use(bodyParser.json());
app.use(cors({
    origin: ['https://vpred-portal-with-plagiarism-detector.onrender.com'],
    methods: ['POST', 'GET'],
    credentials: true
}));

// Helper function to sanitize and validate input
// this is the validator and sanitizer of the input of the user
const sanitizeAndValidate = (input, validationRules) => {

    // clean multiple spaces
    const cleanedInput = input.replace(/\s+/g, ' ');

    const sanitizedInput = sanitizeHtml(cleanedInput.trim());

    for (const rule of validationRules) {
        if (!rule.validator(sanitizedInput)) {
            return false;
        }
    }

    return sanitizedInput;
};

// initialize my secret key
const secretKey = process.env.SECRET_KEY;

// require uploads folder
app.use('/uploads', express.static('uploads'));

// MySQL configuration
const connection = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE,
});

connection.connect((err) => {
    if (err) throw err;
    console.log('Connected to MySQL database');
});

// #####################################################################    CURRENT DATE FORMAT  ######################################################################################
function getCurrentFormattedDate() {
    const options = {
        year: 'numeric',
        month: 'long',
        day: 'numeric',
        hour: 'numeric',
        minute: 'numeric',
        hour12: true
    };

    const currentDate = new Date();
    return new Intl.DateTimeFormat('en-US', options).format(currentDate);
}

// #####################################################################    VERIFY TOKEN SIDE  ######################################################################################
const verifyToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ message: 'Token missing or invalid' });
    } else {
        const token = authHeader.substring('Bearer '.length);

        jwt.verify(token, secretKey, (err, decoded) => {
            if (err) {
                return res.status(401).json({ message: 'Token is expired or invalid' });
            }

            // Store decoded user data in the request
            req.user = decoded;
            next();
        });
    }
};

// ###################################################################################################################################################################################
// #####################################################################  PROTECTED SIDE  ############################################################################################
// ###################################################################################################################################################################################
app.get('/protected', verifyToken, (req, res) => {
    const { user } = req; // Decoded user data from the token

    res.status(200).json({ message: 'Success', user: user });
});

// ###########################################################################################################################################################################
// #############################################################    PLAGIARISM DETECTOR ALGORITHM SIDE   #####################################################################
// #############################################################           USING SEARCH ENGINE          ######################################################################
// ###########################################################################################################################################################################

// process the document to split every sentence
function processFile(filenamePath, callback) {
    fs.readFile(filenamePath, (err, data) => {
        // return error
        if (err) {
            console.error('Error reading file:', err);
            return callback(err);
        }

        // initialize file extension
        const fileType = mime.lookup(filenamePath);
        // initioalize myArray
        let myArray = [];

        // create function that holds the result of array
        function processAndLogArray() {
            callback(null, myArray);
        }

        if (fileType === 'application/pdf') {
            // Extract text from the PDF
            PDFParser(data)
                .then(result => {
                    const content = result.text;

                    // Split the content into sentences
                    const arraySentence = content.split('.');
                    // remove the multiple spaces as well as the leading and trailing space using trim()
                    const filteredSentences = arraySentence.filter(sentence => sentence.trim() !== '');
                    const resultArray = filteredSentences.filter(sentence => sentence.trim() !== '');

                    // remove all index that less than 50 characters
                    const another = resultArray.filter(text => text.length >= 50);

                    myArray = another;
                    processAndLogArray();
                })
                .catch(error => {
                    console.error('Error extracting text:', error);
                    callback(error);
                });
        } else if (fileType === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document') {
            // extract document file
            mammoth.extractRawText({ buffer: data })
                .then(result => {
                    const content = result.value;

                    // Split the content into sentences
                    const arraySentence = content.split('.');

                    const filteredSentences = arraySentence.filter(sentence => sentence.trim() !== '');
                    const resultArray = filteredSentences.filter(sentence => sentence.trim() !== '');

                    const another = resultArray.filter(fruit => fruit.length >= 50);

                    myArray = another;
                    processAndLogArray();
                })
                .catch(error => {
                    console.error('Error extracting text:', error);
                    callback(error);
                });
        } else {
            const unsupportedError = new Error('Unsupported file type');
            callback(unsupportedError)
        }
    });
}
// ####################################################################################################################################################################################
// ###########################################################      PLAGIARISM ALGO AND RESULT FOR PLAGIARIZE      ###################################################################################
// ####################################################################################################################################################################################
app.post('/plagiarize/document', verifyToken, (req, res) => {
    const { filename, id } = req.body;

    // get the current date
    const currentDate = getCurrentFormattedDate();

    // validate
    const validationRules = [
        { validator: validator.isLength, options: { min: 1, max: 50 } }
    ]

    const sanitizeFileName = sanitizeAndValidate(filename, validationRules);
    const dataId = sanitizeAndValidate(id, validationRules);

    const filenamePath = path.join('document upload', sanitizeFileName);

    processFile(filenamePath, (err, processedArray) => {
        if (err) {
            return res.status(401).send('Error processing file');
        }

        // search engin sample
        async function performGoogleSearches(sentences) {
            const allSearchedContentsAndLink = [];
            let countRow = 0;

            for (const sentence of sentences) {
                const url = 'https://www.google.com/search?q=' + encodeURIComponent(sentence);

                try {
                    const response = await axios.get(url, {
                        headers: {
                            'User-Agent':
                                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36',
                        },
                    });

                    const html = response.data;
                    const $ = cheerio.load(html);

                    const searchResults = $('div.Gx5Zad.fP1Qef.xpd.EtOod.pkphOe');

                    let index = 0;
                    searchResults.each((index, element) => {

                        if (index >= 10) {
                            return false; // Break out of the loop after 10 results
                        }

                        const linkElement = $(element).find('a');
                        const link = linkElement.attr('href');
                        // const link = $(element).attr('href');
                        const text = $(element).text();

                        if (link && text) {
                            const textAndLink = link + "|" + text;
                            allSearchedContentsAndLink.push(textAndLink);
                        }

                        index++;
                    });

                    await new Promise(resolve => setTimeout(resolve, 2000)); // Sleep for 2 seconds to avoid blocked by google for spamming
                } catch (error) {
                    // console.error('Error:', error);
                    res.status(401).json({ message: "Something went wrong!" });
                }
            }
            return allSearchedContentsAndLink;
            // console.log("display every result: ", allSearchedContentsAndLink);
        }

        const sentencesToSearch = processedArray;
        performGoogleSearches(sentencesToSearch)
            .then(results => {
                // console.log('Searched contents and links:', results);
                const allSearchedContentsAndLink = results;
                const plagiarizedSentences = [];
                const sentencesPlagiarized = [];
                let finalSimilarityWeight = 0;

                // constrack each word by word
                sentencesToSearch.forEach(sentence => {
                    const words = sentence.split(" ");

                    let taggedAsPlagiarized = false;
                    const thresholdWeightForPlagiarized = Math.ceil(words.length * 0.6);

                    let finalWeight = 0;
                    for (let index = 0; index < allSearchedContentsAndLink.length; index++) {
                        let weight = 0;
                        // Split the sentence to check for comparison
                        const split = allSearchedContentsAndLink[index].split("|");
                        const content = split[1];
                        const link = split[0];

                        words.forEach(word => {
                            if (word !== "") {
                                if (content.includes(word)) {
                                    weight += 1;
                                    finalWeight += 1;
                                }
                            }

                            if (weight >= thresholdWeightForPlagiarized) {
                                taggedAsPlagiarized = true;
                                return; // Break the inner loop
                            }
                        });

                        if (taggedAsPlagiarized) {
                            plagiarizedSentences.push(link);
                            sentencesPlagiarized.push(sentence);

                            finalSimilarityWeight += 1;
                            break;
                        }
                    }
                });

                // similarity
                const finalSimilarity = Math.floor((finalSimilarityWeight / sentencesToSearch.length) * 100);

                // originality
                const originality = 100 - finalSimilarity;


                const finalLinkForPlagiarized = plagiarizedSentences.map(link => {
                    const urlStartIndex = link.indexOf('url=') + 4; // Add 4 to skip 'url='
                    const url = decodeURIComponent(link.substring(urlStartIndex));
                    const splitText = url.split('&ved=');
                    const plagiarizedLink = splitText[0];
                    return plagiarizedLink;
                });

                const combinedContentAndLink = [];

                for (let i = 0; i < sentencesPlagiarized.length; i++) {
                    combinedContentAndLink.push({
                        sentencesPlagiarized: sentencesPlagiarized[i],
                        link: finalLinkForPlagiarized[i]
                    });
                }

                // generate group_code
                const characters = "abcdefjhigklmnopqrstuvwxyzABCDEFJHIGKLMNOPQRSTUVWXYZ1234567890";
                const group_code = Array.from({ length: 15 }, () => characters[Math.floor(Math.random() * characters.length)]).join('');

                // insert result to database
                const resultPromise = combinedContentAndLink.map(item => {
                    return new Promise((resolve, reject) => {
                        const insertResult = 'INSERT INTO plagiarism_result (content, link, originality, similarity, date, plagiarized_data_id, group_code, file_name) VALUES (?, ?, ?, ?, ?, ?, ?, ?)';
                        connection.query(insertResult, [item.sentencesPlagiarized, item.link, originality, finalSimilarity, currentDate, dataId, group_code, sanitizeFileName], (error, results) => {
                            if (error) {
                                reject(error);
                            } else {
                                resolve(results);
                            }
                        })
                    })
                });

                Promise.all(resultPromise).then(() => {
                    // success
                    const insertToData = 'UPDATE all_research_data SET group_code = ?, isScan = ? WHERE id = ?';
                    connection.query(insertToData, [group_code, "scanned", dataId], (error, results) => {
                        if (error) {
                            res.status(401).json({ message: "Server side error!" });
                        } else {
                            // insert originality and similarity to all research and extension table on database
                            const insertSO = 'UPDATE all_research_data SET originality = ?, similarity = ? WHERE id = ?';
                            connection.query(insertSO, [originality, finalSimilarity, dataId], (error, results) => {
                                if (error) {
                                    res.status(401).json({ message: "Server side error!" });
                                } else {
                                    res.status(200).json({ combinedContentAndLink: combinedContentAndLink, originality: originality, similarity: finalSimilarity });
                                }
                            });
                        }
                    });
                })
                    .catch(resultError => {
                        // if error
                        res.status(401).json({ message: "Something went wrong!" });
                    });

            })
            .catch(error => {
                console.error('An error occurred:', error);
                res.status(401).json({ message: "An error occured" });
            });
    });
});

// end of plagiarism algorithm using search engine

// ###########################################################################################################################################################################
// #####################################################################    LOGIN SIDE   ######################################################################################
// ###########################################################################################################################################################################
app.post('/login', (req, res) => {
    const { email, password } = req.body;
    const isDelete = "not";

    const validationRules = [
        { validator: validator.isLength, options: { min: 1, max: 50 } },
        // {validator: validator.isEmail, options: {min: 1, max: 50}}
    ]

    const sanitizeEmail = sanitizeAndValidate(email, validationRules);
    const sanitizePassword = sanitizeAndValidate(password, validationRules);

    if (!sanitizeEmail || !sanitizePassword) {
        res.status(401).json({ message: "Invalid Input!" });
    }

    else {
        const hashedPassword = crypto.createHash('sha256').update(sanitizePassword).digest('hex');
        const query = `SELECT * FROM users WHERE email = '${sanitizeEmail}' AND password = '${hashedPassword}' AND isDelete = '${isDelete}'`;

        connection.query(query, (err, results) => {
            if (err) throw err;

            if (results.length > 0) {

                // fetch id and email
                const fetchData = {
                    id: results[0].id,
                    email: results[0].email,
                    password: results[0].password,
                    rank: results[0].rank
                };

                // const token = jwt.sign(fetchData, secretKey, { expiresIn: '1h' });
                const token = jwt.sign(fetchData, secretKey);

                // res.cookie(token);
                res.status(200).json({ token: token, rank: results[0].rank });
                // res.status(200).json({results});
            } else {
                res.status(401).json({ message: 'Invalid credentials' });
            }
        });
    }
});

// ###################################################################################################################################################################################
// #####################################################################    FETCH USER DATA USING ID  ################################################################################
// ###################################################################################################################################################################################
app.get('/api/getData/:id', verifyToken, (req, res) => {
    const id = req.params.id;

    const query = `SELECT * FROM users WHERE id = '${id}'`;

    connection.query(query, (error, results) => {

        if (error) {
            console.log("Error: ", error);
            // res.status(500).json({ message: 'Error fetching data' });
        } else {
            res.status(200).json({ results });
        }
    });
});

// #########################################################################################################################################################################################################
// ##########################################################################        ADMIN SIDE           ##################################################################################################
// #########################################################################################################################################################################################################

// #####################################################################    REGISTER UNIT HEAD ACCOUNT  ######################################################################################
app.post('/add-unit-head', verifyToken, (req, res) => {

    const { RorE, campus, fullname, email, generatedPassword, user_id } = req.body;
    const givenImage = "givenProfile.png";
    const addedBy = "Admin";
    const givenRank = "Unit Head";

    // get the current date
    const currentDate = getCurrentFormattedDate();

    const validationRules = [
        { validator: validator.isLength, options: { min: 1, max: 50 } },
    ]

    const sanitizeRorE = sanitizeAndValidate(RorE, validationRules);
    const sanitizeCampus = sanitizeAndValidate(campus, validationRules);
    const sanitizeFullname = sanitizeAndValidate(fullname, validationRules);
    const sanitizeEmail = sanitizeAndValidate(email, validationRules);
    const sanitizePassword = sanitizeAndValidate(generatedPassword, validationRules);
    const sanitizeUserId = sanitizeAndValidate(user_id, validationRules);

    if (!sanitizeRorE || !sanitizeCampus || !sanitizeFullname || !sanitizeEmail || !sanitizePassword || !sanitizeUserId) {
        res.status(401).json({ message: "Invalid Input!" });
    }
    else {
        // check the password length
        if (sanitizePassword.length < 5) {
            res.status(401).json({ message: "Password must have at least 5 characters!" });
            return;
        }

        // check if email is already in used
        const checkEmail = 'SELECT * FROM users WHERE email = ? AND rank = ? AND isDelete = ?';
        connection.query(checkEmail, [sanitizeEmail, givenRank, "not"], (error, results) => {
            if (error) {
                res.status(401).json({ message: 'Server side error!' });
            }
            else {
                if (results.length === 0) {
                    // create password hash
                    const passwordHash = crypto.createHash('sha256').update(sanitizePassword).digest('hex');

                    // Insert image path into MySQL database
                    const sql = 'INSERT INTO users (RorE, campus, fullname, email, password, image, added_by, rank, date) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)';
                    connection.query(sql, [sanitizeRorE, sanitizeCampus, sanitizeFullname, sanitizeEmail, passwordHash, givenImage, addedBy, givenRank, currentDate], (err, result) => {
                        if (err) {
                            console.error('Error inserting data into MySQL:', err);
                            res.status(401).json({ message: 'Error uploading data to the server.' });
                        } else {
                            // get the inserted id
                            const receiverId = result.insertId;

                            // send notification for sender
                            const senderContent = `You added ${sanitizeFullname} as Unit Head from ${sanitizeCampus} campus`;
                            const receiverContent = "Admin added your account";

                            // insert sender notification
                            const senderData = 'INSERT INTO notification (user_id, content, date) VALUES (?, ?, ?)';
                            connection.query(senderData, [sanitizeUserId, senderContent, currentDate], (error, results) => {
                                if (error) {
                                    res.status(401).json({ message: "Server side error!" });
                                } else {
                                    // insert receiver notification
                                    const receiverData = 'INSERT INTO notification (user_id, content, date) VALUES (?, ?, ?)';
                                    connection.query(receiverData, [receiverId, receiverContent, currentDate], (error, results) => {
                                        if (error) {
                                            res.status(401).json({ message: "Server side error" });
                                        } else {
                                            // send verification code to email
                                            const body = `Hi ${sanitizeFullname} You can now access to JRMSU Research Development And Extension Portal from ${sanitizeRorE.toUpperCase()} in ${sanitizeCampus.toUpperCase()} as ${givenRank.toUpperCase()} using this Email: ${sanitizeEmail.toUpperCase()} and Password: ${sanitizePassword} \n\n. Click here to login (sample link here!)`;

                                            var transporter = nodemailer.createTransport({
                                                service: 'gmail',
                                                auth: {
                                                    user: 'jrmsuvpred@gmail.com',
                                                    pass: 'kbwyyjspjdjerrno'
                                                }
                                            });

                                            var mailOptions = {
                                                from: 'jrmsuvpred@gmail.com',
                                                to: sanitizeEmail,
                                                subject: 'Your verification code!',
                                                text: body
                                            };

                                            transporter.sendMail(mailOptions, function (error, info) {
                                                if (error) {
                                                    console.log(error);
                                                } else {
                                                    res.status(200).json({ message: 'Account has been successfully added and was sent to email successfully!' });
                                                }
                                            });
                                        }
                                    });
                                }
                            });
                        }
                    });
                }
                else {
                    res.status(401).json({ message: 'Email is already in used! Please try again!' });
                }
            }
        });
    }
});

// #####################################################################    FETCH ALL UNIT HEAD ACCOUNT  ######################################################################################
app.get('/fetch/all-unit-head', verifyToken, (req, res) => {
    // fetch data
    const unitData = 'SELECT * FROM users WHERE rank = ? AND isDelete = ?';
    connection.query(unitData, ["Unit Head", "not"], (error, results) => {
        if (error) {
            res.status(401).json({ message: 'Server side error!' });
        }
        else {
            if (results.length > 0) {
                //success
                res.status(200).json({ results });
            }
            else {
                res.status(401).json({ message: "Something went wrong!" });
            }
        }
    });
});

// #####################################################################    UPDATE UNIT HEAD  ######################################################################################
app.post('/update/unit-head', verifyToken, (req, res) => {
    const { updateIdString, updateRorEString, updateCampusString, updateFullnameString, updateEmailString, updateCurrentEmailString, user_id } = req.body;
    // get current date
    const currentDate = getCurrentFormattedDate();

    const validationRules = [
        { validator: validator.isLength, options: { min: 1, max: 50 } },
    ]

    const sanitizeUpdateId = sanitizeAndValidate(updateIdString, validationRules);
    const sanitizeUpdateRorE = sanitizeAndValidate(updateRorEString, validationRules);
    const sanitizeUpdateCampus = sanitizeAndValidate(updateCampusString, validationRules);
    const sanitizeUpdateFullname = sanitizeAndValidate(updateFullnameString, validationRules);
    const sanitizeUpdateEmail = sanitizeAndValidate(updateEmailString, validationRules);
    const sanitizeCurrentEmail = sanitizeAndValidate(updateCurrentEmailString, validationRules);
    const sanitizeUserId = sanitizeAndValidate(user_id, validationRules);

    if (!sanitizeUpdateId || !sanitizeUpdateRorE || !sanitizeUpdateCampus || !sanitizeUpdateFullname || !sanitizeUpdateEmail || !sanitizeCurrentEmail || !sanitizeUserId) {
        res.status(401).json({ message: "Invalid Input!" });
    } else {
        const checkEmail = 'SELECT * FROM users WHERE email = ? AND id != ? AND rank = ? AND isDelete = ?';
        connection.query(checkEmail, [sanitizeUpdateEmail, sanitizeUpdateId, "Unit Head", "not"], (error, results) => {
            if (error) {
                res.status(401).json({ message: "Server side error!" });
            } else {
                if (results.length > 0) {
                    res.status(401).json({ message: "Email is already in used! Please try again!" });
                }
                else {
                    const updateData = 'UPDATE users SET RorE = ?, campus = ?, fullname = ?, email = ? WHERE id = ?';
                    connection.query(updateData, [sanitizeUpdateRorE, sanitizeUpdateCampus, sanitizeUpdateFullname, sanitizeUpdateEmail, sanitizeUpdateId], (error, results) => {
                        if (error) {
                            res.status(401).json({ message: "Server side error!" });
                        } else {
                            if (results.length > 0) {
                                res.status(401).json({ message: "Something went wrong!" });
                            } else {
                                // send notification
                                const receiverContent = `Admin updated your accout!`;

                                // insert notification to database
                                const receiverData = 'INSERT INTO notification (user_id, content, date) VALUES (?, ?, ?)';
                                connection.query(receiverData, [sanitizeUpdateId, receiverContent, currentDate], (error, results) => {
                                    if (error) {
                                        res.status(401).json({ message: "Server side error" });
                                    } else {
                                        // initialize test
                                        let test;

                                        // check the current email and updated email
                                        if (sanitizeCurrentEmail === sanitizeUpdateEmail) {
                                            test = true;
                                        } else {
                                            test = false;
                                        }

                                        const body = `Your account on jrmsu vpred as Unit Head was updated to ${sanitizeUpdateRorE.toUpperCase()}, Campus: ${sanitizeUpdateCampus.toUpperCase()}, Name: ${sanitizeUpdateFullname.toUpperCase()} and Email: ${sanitizeUpdateEmail.toUpperCase()}`;

                                        var transporter = nodemailer.createTransport({
                                            service: 'gmail',
                                            auth: {
                                                user: 'jrmsuvpred@gmail.com',
                                                pass: 'kbwyyjspjdjerrno'
                                            }
                                        });

                                        var mailOptions = {
                                            from: 'jrmsuvpred@gmail.com',
                                            to: sanitizeCurrentEmail,
                                            subject: 'Account update status!',
                                            text: body
                                        };

                                        if (test) {
                                            transporter.sendMail(mailOptions, function (error, info) {
                                                if (error) {
                                                    console.log(error);
                                                } else {
                                                    res.status(200).json({ message: 'Account has been successfully Updated and was sent to email successfully!' });
                                                }
                                            });
                                        } else {
                                            transporter.sendMail(mailOptions, function (error, info) {
                                                if (error) {
                                                    console.log(error);
                                                } else {

                                                    const newBody = `Your account on jrmsu vpred as Unit Head was updated to this Email: ${sanitizeUpdateEmail.toUpperCase()}. \n\nvisit for more on this link: (sample link)`;

                                                    var newMailOption = {
                                                        from: 'jrmsuvpred@gmail.com',
                                                        to: sanitizeUpdateEmail,
                                                        subject: 'Your verification code!',
                                                        text: newBody
                                                    };

                                                    transporter.sendMail(newMailOption, function (error, info) {
                                                        if (error) {
                                                            console.log(error);
                                                        } else {
                                                            res.status(200).json({ message: 'Account has been successfully Updated and was sent to email successfully!' });
                                                        }
                                                    });
                                                }
                                            });
                                        }
                                    }
                                })
                            }
                        }
                    });
                }
            }
        });
    }
});

// #####################################################################    DELETE UNIT HEAD ACCOUNT  ######################################################################################
app.post('/delete/unit-head', verifyToken, (req, res) => {
    const { deleteIdString, deleteEmailString } = req.body;

    const validationRules = [
        { validator: validator.isLength, options: { min: 1, max: 50 } }
    ]

    const sanitizeDelete = sanitizeAndValidate(deleteIdString, validationRules);
    const sanitizeDeleteEmail = sanitizeAndValidate(deleteEmailString, validationRules);

    if (!sanitizeDelete || !sanitizeDeleteEmail) {
        res.status(401).json({ message: "Invalid Input!" });
    } else {
        // delete
        const deleteId = 'UPDATE users SET isDelete = ? WHERE id = ?';
        connection.query(deleteId, ["Deleted", sanitizeDelete], (error, results) => {
            if (error) {
                res.status(401).json({ message: "Server side error!" });
            } else {
                // send to email
                const body = `Your account on jrmsu vpred as Unit Head was been deleted by Admin. You can't no longer access on the portal`;

                var transporter = nodemailer.createTransport({
                    service: 'gmail',
                    auth: {
                        user: 'jrmsuvpred@gmail.com',
                        pass: 'kbwyyjspjdjerrno'
                    }
                });

                var mailOptions = {
                    from: 'jrmsuvpred@gmail.com',
                    to: sanitizeDeleteEmail,
                    subject: 'Your account was deleted!',
                    text: body
                };

                transporter.sendMail(mailOptions, function (error, info) {
                    if (error) {
                        console.log(error);
                    } else {
                        res.status(200).json({ message: "Account has been deleted uccessfully!" });
                    }
                });
            }
        });
    }
});

// #####################################################################    ADD CHAIRPERSON ACCOUNT  ######################################################################################
app.post('/add-chairperson', verifyToken, (req, res) => {
    const { RorE, campus, college, fullname, email, password, user_id, userRank } = req.body;
    const givenImage = "givenProfile.png";

    // fetch current date
    const currentDate = getCurrentFormattedDate();

    const validationRules = [
        { validator: validator.isLength, options: { min: 1, max: 50 } }
    ];

    const validatedRorE = sanitizeAndValidate(RorE, validationRules);
    const validatedCampus = sanitizeAndValidate(campus, validationRules);
    const validatedCollege = sanitizeAndValidate(college, validationRules);
    const validatedFullname = sanitizeAndValidate(fullname, validationRules);
    const validatedEmail = sanitizeAndValidate(email, validationRules);
    const validatedPassword = sanitizeAndValidate(password, validationRules);
    const sanitizeUserId = sanitizeAndValidate(user_id, validationRules);
    const addedBy = sanitizeAndValidate(userRank, validationRules);

    if (!validatedRorE || !validatedCampus || !validatedCollege || !validatedFullname || !validatedEmail || !validatedPassword || !sanitizeUserId || !addedBy) {
        res.status(401).json({ message: "Invalid Input!" });
    }
    else {
        // check the password length
        if (validatedPassword.length < 5) {
            res.status(401).json({ message: "Password must have at least 5 characters!" });
            return;
        }

        // const cCheckEmail = 'SELECT * FROM users WHERE email = ? AND rank = ? AND isDelete = ?';
        const cCheckEmail = `SELECT * FROM users WHERE email = '${email}' AND rank = 'Chairperson' AND isDelete = 'not'`;
        connection.query(cCheckEmail, (error, results) => {
            if (error) {
                res.status(401).json({ message: "Server side error!" });
            }
            else {
                if (results.length === 0) {
                    // success
                    // hash password
                    const hashedPassword = crypto.createHash('sha256').update(validatedPassword).digest('hex');
                    const insert = `INSERT INTO users (RorE, campus, college, fullname, email, password, added_by, image, date, rank) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;
                    connection.query(insert, [validatedRorE, validatedCampus, validatedCollege, validatedFullname, validatedEmail, hashedPassword, addedBy, givenImage, currentDate, "Chairperson"], (error, results) => {
                        if (error) {
                            res.status(401).json({ message: "Server side error!" });
                        }
                        else {
                            // get inserted id
                            const receiverId = results.insertId;

                            // initialize sender and receiver content
                            const senderContent = `You added ${validatedFullname} as Chairperson at ${validatedCampus} campus college of ${validatedCollege}`;
                            const receiverContent = `${addedBy} added your account`;

                            // insert into database
                            const senderData = 'INSERT INTO notification (user_id, content, date) VALUES (?, ?, ?)';
                            connection.query(senderData, [sanitizeUserId, senderContent, currentDate], (error, results) => {
                                if (error) {
                                    res.status(401).json({ message: "Server side error" });
                                } else {
                                    // insert reciever notification
                                    const receiverData = 'INSERT INTO notification (user_id, content, date) VALUES (?, ?, ?)';
                                    connection.query(receiverData, [receiverId, receiverContent, currentDate], (error, results) => {
                                        if (error) {
                                            res.status(401).json({ message: "Server side error!" });
                                        } else {
                                            // send to email
                                            const body = `Hi ${validatedFullname}, ${addedBy} added your account on JRMSU-VPRED using this Email: ${validatedEmail} and Password: ${password} \n\n.Click here to login (sample link here!)`;

                                            var transporter = nodemailer.createTransport({
                                                service: 'gmail',
                                                auth: {
                                                    user: 'jrmsuvpred@gmail.com',
                                                    pass: 'kbwyyjspjdjerrno'
                                                }
                                            });

                                            var mailOptions = {
                                                from: 'jrmsuvpred@gmail.com',
                                                to: validatedEmail,
                                                subject: 'Your verification code!',
                                                text: body
                                            };

                                            transporter.sendMail(mailOptions, function (error, info) {
                                                if (error) {
                                                    console.log(error);
                                                } else {
                                                    res.status(200).json({ message: 'Account has been successfully added and was sent to email successfully!' });
                                                }
                                            });
                                        }
                                    });
                                }
                            });
                        }
                    });
                }
                else {
                    res.status(401).json({ message: "Email is already in used! Please try again!" });
                }
            }
        });
    }
})

// #####################################################################    FETCH ALL CHAIRPERSON ACCOUNT  ######################################################################################
app.get('/fetch/all-chairperson', verifyToken, (req, res) => {
    // fetch data
    const unitData = 'SELECT * FROM users WHERE rank = ? AND isDelete = ?';
    connection.query(unitData, ["Chairperson", "not"], (error, results) => {
        if (error) {
            res.status(401).json({ message: 'Server side error!' });
        }
        else {
            if (results.length > 0) {
                //success
                res.status(200).json({ results });
            }
            else {
                res.status(401).json({ message: "Something went wrong!" });
            }
        }
    });
});

// #####################################################################    UPDATE CHAIRPERSON ACCOUNT  ######################################################################################
app.post('/update/chairperson', verifyToken, (req, res) => {
    const { updateIdString, updateRorEString, updateCampusString, updateFullnameString, updateEmailString, updateCurrentEmailString, updateCollegeString, userRank } = req.body;
    // get current date
    const currentDate = getCurrentFormattedDate();

    const validationRules = [
        { validator: validator.isLength, options: { min: 1, max: 50 } },
    ]

    const sanitizeUpdateId = sanitizeAndValidate(updateIdString, validationRules);
    const sanitizeUpdateRorE = sanitizeAndValidate(updateRorEString, validationRules);
    const sanitizeUpdateCampus = sanitizeAndValidate(updateCampusString, validationRules);
    const sanitizeUpdateFullname = sanitizeAndValidate(updateFullnameString, validationRules);
    const sanitizeUpdateEmail = sanitizeAndValidate(updateEmailString, validationRules);
    const sanitizeCurrentEmail = sanitizeAndValidate(updateCurrentEmailString, validationRules);
    const sanitizeCollege = sanitizeAndValidate(updateCollegeString, validationRules);
    const addedBy = sanitizeAndValidate(userRank, validationRules);

    if (!sanitizeUpdateId || !sanitizeUpdateRorE || !sanitizeUpdateCampus || !sanitizeUpdateFullname || !sanitizeUpdateEmail || !sanitizeCurrentEmail || !sanitizeCollege || !addedBy) {
        res.status(401).json({ message: "Invalid Input!" });
    } else {
        const checkEmail = 'SELECT * FROM users WHERE email = ? AND id != ? AND rank = ? AND isDelete = ?';
        connection.query(checkEmail, [sanitizeUpdateEmail, sanitizeUpdateId, "Chairperson", "not"], (error, results) => {
            if (error) {
                res.status(401).json({ message: "Server side error!" });
            } else {
                if (results.length > 0) {
                    res.status(401).json({ message: "Email is already in used! Please try again!" });
                }
                else {
                    const updateData = 'UPDATE users SET RorE = ?, campus = ?, fullname = ?, email = ?, college = ? WHERE id = ?';
                    connection.query(updateData, [sanitizeUpdateRorE, sanitizeUpdateCampus, sanitizeUpdateFullname, sanitizeUpdateEmail, sanitizeCollege, sanitizeUpdateId], (error, results) => {
                        if (error) {
                            res.status(401).json({ message: "Server side error!" });
                        } else {
                            if (results.length > 0) {
                                res.status(401).json({ message: "Something went wrong!" });
                            } else {
                                // initialize receiver content
                                const receiverContent = `${addedBy} updated your account`;

                                // insert notification to database
                                const receiverData = 'INSERT INTO notification (user_id, content, date) VALUES (?, ? ,?)';
                                connection.query(receiverData, [sanitizeUpdateId, receiverContent, currentDate], (error, results) => {
                                    if (error) {
                                        res.status(401).json({ message: "Server side error" });
                                    } else {
                                        let test;

                                        // check the current email and updated email
                                        if (sanitizeCurrentEmail === sanitizeUpdateEmail) {
                                            test = true;
                                        } else {
                                            test = false;
                                        }

                                        const body = `Your account on jrmsu vpred as Chairperson was updated by the ${addedBy}\n\nvisit this link to login: (sample link)`;

                                        var transporter = nodemailer.createTransport({
                                            service: 'gmail',
                                            auth: {
                                                user: 'jrmsuvpred@gmail.com',
                                                pass: 'kbwyyjspjdjerrno'
                                            }
                                        });

                                        var mailOptions = {
                                            from: 'jrmsuvpred@gmail.com',
                                            to: sanitizeCurrentEmail,
                                            subject: 'Account update status!',
                                            text: body
                                        };

                                        if (test) {
                                            transporter.sendMail(mailOptions, function (error, info) {
                                                if (error) {
                                                    console.log(error);
                                                } else {
                                                    res.status(200).json({ message: 'Account has been successfully Updated and was sent to email successfully!' });
                                                }
                                            });
                                        } else {
                                            transporter.sendMail(mailOptions, function (error, info) {
                                                if (error) {
                                                    console.log(error);
                                                } else {

                                                    const newBody = `Your account on jrmsu vpred as Chairperson was updated to this Email: ${sanitizeUpdateEmail.toUpperCase()}. \n\nvisit for more on this link: (sample link)`;

                                                    var newMailOption = {
                                                        from: 'jrmsuvpred@gmail.com',
                                                        to: sanitizeUpdateEmail,
                                                        subject: 'Your verification code!',
                                                        text: newBody
                                                    };

                                                    transporter.sendMail(newMailOption, function (error, info) {
                                                        if (error) {
                                                            console.log(error);
                                                        } else {
                                                            res.status(200).json({ message: 'Account has been successfully Updated and was sent to email successfully!' });
                                                        }
                                                    });
                                                }
                                            });
                                        }
                                    }
                                });
                            }
                        }
                    });
                }
            }
        });
    }
});

// #####################################################################    DELETE CHAIRPERSON ACCOUNT  ######################################################################################
app.post('/delete/chairperson', verifyToken, (req, res) => {
    const { deleteIdString, deleteEmailString, userRank } = req.body;

    const validationRules = [
        { validator: validator.isLength, options: { min: 1, max: 50 } }
    ]

    const sanitizeDelete = sanitizeAndValidate(deleteIdString, validationRules);
    const sanitizeDeleteEmail = sanitizeAndValidate(deleteEmailString, validationRules);
    const rank = sanitizeAndValidate(userRank, validationRules);

    if (!sanitizeDelete || !sanitizeDeleteEmail) {
        res.status(401).json({ message: "Invalid Input!" });
    } else {
        // delete
        const deleteId = 'UPDATE users SET isDelete = ? WHERE id = ?';
        connection.query(deleteId, ["Deleted", sanitizeDelete], (error, results) => {
            if (error) {
                res.status(401).json({ message: "Server side error!" });
            } else {
                // send to email
                const body = `Your account on jrmsu vpred as Chairperson was been deleted by ${rank}. You can't no longer access on the portal`;

                var transporter = nodemailer.createTransport({
                    service: 'gmail',
                    auth: {
                        user: 'jrmsuvpred@gmail.com',
                        pass: 'kbwyyjspjdjerrno'
                    }
                });

                var mailOptions = {
                    from: 'jrmsuvpred@gmail.com',
                    to: sanitizeDeleteEmail,
                    subject: 'Your account was deleted!',
                    text: body
                };

                transporter.sendMail(mailOptions, function (error, info) {
                    if (error) {
                        console.log(error);
                    } else {
                        res.status(200).json({ message: "Account has been deleted uccessfully!" });
                    }
                });
            }
        });
    }
});

// #####################################################################    FETCH ALL AUTHOR ACCOUNT  ######################################################################################
app.get('/fetch/all-author', verifyToken, (req, res) => {
    // fetch data
    const unitData = 'SELECT * FROM users WHERE rank = ? AND isDelete = ?';
    connection.query(unitData, ["Author", "not"], (error, results) => {
        if (error) {
            res.status(401).json({ message: 'Server side error!' });
        }
        else {
            if (results.length > 0) {
                //success
                res.status(200).json({ results });
            }
            else {
                res.status(401).json({ message: "Something went wrong!" });
            }
        }
    });
});

// #####################################################################    UPDATE AUTHOR ACCOUNT  ######################################################################################
app.post('/update/author', verifyToken, (req, res) => {
    const { updateIdString, updateRorEString, updateCampusString, updateFullnameString, updateEmailString, updateCurrentEmailString, updateCollegeString, userRank } = req.body;
    // get current date
    const currentDate = getCurrentFormattedDate();

    const validationRules = [
        { validator: validator.isLength, options: { min: 1, max: 50 } },
    ]

    const sanitizeUpdateId = sanitizeAndValidate(updateIdString, validationRules);
    const sanitizeUpdateRorE = sanitizeAndValidate(updateRorEString, validationRules);
    const sanitizeUpdateCampus = sanitizeAndValidate(updateCampusString, validationRules);
    const sanitizeUpdateFullname = sanitizeAndValidate(updateFullnameString, validationRules);
    const sanitizeUpdateEmail = sanitizeAndValidate(updateEmailString, validationRules);
    const sanitizeCurrentEmail = sanitizeAndValidate(updateCurrentEmailString, validationRules);
    const sanitizeCollege = sanitizeAndValidate(updateCollegeString, validationRules);
    const rank = sanitizeAndValidate(userRank, validationRules);

    if (!sanitizeUpdateId || !sanitizeUpdateRorE || !sanitizeUpdateCampus || !sanitizeUpdateFullname || !sanitizeUpdateEmail || !sanitizeCurrentEmail || !sanitizeCollege || !rank) {
        res.status(401).json({ message: "Invalid Input!" });
    } else {
        const updateData = 'UPDATE users SET RorE = ?, campus = ?, fullname = ?, email = ?, college = ? WHERE id = ?';
        connection.query(updateData, [sanitizeUpdateRorE, sanitizeUpdateCampus, sanitizeUpdateFullname, sanitizeUpdateEmail, sanitizeCollege, sanitizeUpdateId], (error, results) => {
            if (error) {
                res.status(401).json({ message: "Server side error!" });
            } else {
                if (results.length > 0) {
                    res.status(401).json({ message: "Something went wrong!" });
                } else {
                    // initialize receiver content
                    const receiverContent = `${rank} updated your account`;

                    // insert notification to database
                    const receiverData = 'INSERT INTO notification (user_id, content, date) VALUES (?, ? ,?)';
                    connection.query(receiverData, [sanitizeUpdateId, receiverContent, currentDate], (error, results) => {
                        if (error) {
                            res.status(401).json({ message: "Server side error" });
                        } else {
                            let test;

                            // check the current email and updated email
                            if (sanitizeCurrentEmail === sanitizeUpdateEmail) {
                                test = true;
                            } else {
                                test = false;
                            }

                            const body = `Your account on jrmsu vpred as Author was updated by ${rank}`;

                            var transporter = nodemailer.createTransport({
                                service: 'gmail',
                                auth: {
                                    user: 'jrmsuvpred@gmail.com',
                                    pass: 'kbwyyjspjdjerrno'
                                }
                            });

                            var mailOptions = {
                                from: 'jrmsuvpred@gmail.com',
                                to: sanitizeCurrentEmail,
                                subject: 'Account update status!',
                                text: body
                            };

                            if (test) {
                                transporter.sendMail(mailOptions, function (error, info) {
                                    if (error) {
                                        console.log(error);
                                    } else {
                                        res.status(200).json({ message: 'Account has been successfully Updated and was sent to email successfully!' });
                                    }
                                });
                            } else {
                                transporter.sendMail(mailOptions, function (error, info) {
                                    if (error) {
                                        console.log(error);
                                    } else {

                                        const newBody = `Your account on jrmsu vpred as Author was updated to this Email: ${sanitizeUpdateEmail.toUpperCase()}. \n\nvisit for more on this link: (sample link)`;

                                        var newMailOption = {
                                            from: 'jrmsuvpred@gmail.com',
                                            to: sanitizeUpdateEmail,
                                            subject: 'Your verification code!',
                                            text: newBody
                                        };

                                        transporter.sendMail(newMailOption, function (error, info) {
                                            if (error) {
                                                console.log(error);
                                            } else {
                                                res.status(200).json({ message: 'Account has been successfully Updated and was sent to email successfully!' });
                                            }
                                        });
                                    }
                                });
                            }
                        }
                    });
                }
            }
        });
    }
});

// #####################################################################    DELETE AUTHOR ACCOUNT  ######################################################################################
app.post('/delete/author', verifyToken, (req, res) => {
    const { deleteIdString, deleteEmailString, userRank } = req.body;

    const validationRules = [
        { validator: validator.isLength, options: { min: 1, max: 50 } }
    ]

    const sanitizeDelete = sanitizeAndValidate(deleteIdString, validationRules);
    const sanitizeDeleteEmail = sanitizeAndValidate(deleteEmailString, validationRules);
    const rank = sanitizeAndValidate(userRank, validationRules);

    if (!sanitizeDelete || !sanitizeDeleteEmail || !rank) {
        res.status(401).json({ message: "Invalid Input!" });
    } else {
        // delete
        const deleteId = 'UPDATE users SET isDelete = ? WHERE id = ?';
        connection.query(deleteId, ["Deleted", sanitizeDelete], (error, results) => {
            if (error) {
                res.status(401).json({ message: "Server side error!" });
            } else {
                // send to email
                const body = `Your account on jrmsu vpred as Author was been deleted by ${rank}. You can't no longer access on the portal`;

                var transporter = nodemailer.createTransport({
                    service: 'gmail',
                    auth: {
                        user: 'jrmsuvpred@gmail.com',
                        pass: 'kbwyyjspjdjerrno'
                    }
                });

                var mailOptions = {
                    from: 'jrmsuvpred@gmail.com',
                    to: sanitizeDeleteEmail,
                    subject: 'Your account was deleted!',
                    text: body
                };

                transporter.sendMail(mailOptions, function (error, info) {
                    if (error) {
                        console.log(error);
                    } else {
                        res.status(200).json({ message: "Account has been deleted uccessfully!" });
                    }
                });
            }
        });
    }
});

// ######################################################################  ADDING DATA AND DOCUMENT ########################################################################################
const documentUpload = multer({
    dest: 'document upload/',
});

// another sample add image
app.post('/add-data', verifyToken, documentUpload.single('file'), (req, res) => {

    const originalFileName = req.file.originalname;
    const { RorE, campus, college, research, status, proposed, started, completed, inputData, user_id, userRank } = req.body;

    // get the current date
    const currentDate = getCurrentFormattedDate();

    // authors and emails
    const authorsAndEmails = JSON.parse(inputData);

    // validate
    const validationRules = [
        { validator: validator.isLength, options: { min: 1, max: 255 } },
    ]

    // check if all field is not empty
    if (college === "" || proposed === "") {
        res.status(401).json({ message: "Invalid College or Proposed date!" });
        return;
    }

    // check the status
    let checkProposed = false;
    let checkOngoing = false;
    let checkCompleted = false;
    let proposedValue, onGoingValue, completedValue;
    let proposedSanitize, startedSanitize, completedSanitize;

    if (status === "Proposed") {
        checkProposed = true;
        proposedSanitize = sanitizeAndValidate(proposed, validationRules);
        if (!proposedSanitize) {
            res.status(401).json({ message: "Invalid Proposed Input!" });
            return;
        }
        proposedValue = proposedSanitize;
        onGoingValue = "";
        completedValue = "";
    } else if (status === "On-Going") {
        checkProposed = true;
        checkOngoing = true;
        proposedSanitize = sanitizeAndValidate(proposed, validationRules);
        startedSanitize = sanitizeAndValidate(started, validationRules);
        if (!proposedSanitize || !startedSanitize) {
            res.status(401).json({ message: "Invalid Proposed or Started Input!" });
            return;
        }
        proposedValue = proposedSanitize;
        onGoingValue = startedSanitize;
        completedValue = "";
    } else if (status === "Completed") {
        checkProposed = true;
        checkOngoing = true;
        checkCompleted = true;
        proposedSanitize = sanitizeAndValidate(proposed, validationRules);
        startedSanitize = sanitizeAndValidate(started, validationRules);
        completedSanitize = sanitizeAndValidate(completed, validationRules);
        if (!proposedSanitize || !startedSanitize || !completedSanitize) {
            res.status(401).json({ message: "Invalid Proposed, Started, or Completed Input!" });
            return;
        }
        proposedValue = proposedSanitize;
        onGoingValue = startedSanitize;
        completedValue = completedSanitize;
    }

    const RorESanitize = sanitizeAndValidate(RorE, validationRules);
    const campusSanitize = sanitizeAndValidate(campus, validationRules);
    const collegeSanitize = sanitizeAndValidate(college, validationRules);
    const researchSanitize = sanitizeAndValidate(research, validationRules);
    const statusSanitize = sanitizeAndValidate(status, validationRules);
    const userIdSanitize = sanitizeAndValidate(user_id, validationRules);
    const rank = sanitizeAndValidate(userRank, validationRules);

    if (!RorESanitize || !campusSanitize || !collegeSanitize || !researchSanitize || !statusSanitize || !userIdSanitize || !rank) {
        res.status(401).json({ message: "Invalid Input!" });
    }
    else {
        // const fileExtension = originalFileName.split('.').pop();

        const uniqueFileName = `${Date.now()}_+_${originalFileName}`;
        const uniqueFilePath = `document upload/${uniqueFileName}`;

        // Move to uploaded file to the unique file path
        fs.rename(req.file.path, uniqueFilePath, (err) => {
            if (err) {
                res.status(401).json({ message: "Error moving the upload file!" });
            } else {
                const sanitizedFileName = sanitizeHtml(req.file.originalname); // Sanitize HTML content
                if (!validator.isLength(sanitizedFileName, { min: 1, max: 255 })) {
                    return res.status(401).send({ message: "Invalid File Name!" });
                }
                else {
                    if (req.file.size > 5242880) {
                        res.status(401).json({ message: "File is too large!" });
                    }
                    else {
                        // Check if the uploaded file has a PDF or DOCX extension
                        const mimeType = mime.lookup(sanitizedFileName);
                        if (mimeType !== 'application/pdf' && mimeType !== 'application/vnd.openxmlformats-officedocument.wordprocessingml.document') {
                            res.status(401).json({ message: "Invalid file type! Accepted file PDF and Docx extension." })
                        }

                        else {

                            const query = 'INSERT INTO all_research_data (file_name, RorE, campus, college, research, status, proposed, started, completed, added_by, date, user_source_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)';
                            connection.query(query, [uniqueFileName, RorESanitize, campusSanitize, collegeSanitize, researchSanitize, statusSanitize, proposedValue, onGoingValue, completedValue, rank, currentDate, userIdSanitize], (err, results) => {
                                if (err) {
                                    res.status(401).json({ message: "Server side error!" });
                                }
                                else {
                                    // get inserted id
                                    const insertedDataId = results.insertId;

                                    // send notification to sender
                                    const senderContent = `You've successfully added ${researchSanitize} to ${collegeSanitize}`;
                                    const receiverContent = `${rank} added your ${researchSanitize}`;

                                    // insert sender notification
                                    const senderNotification = 'INSERT INTO notification (user_id, content, date) VALUES (?, ?, ?)';
                                    connection.query(senderNotification, [userIdSanitize, senderContent, currentDate], (error, results) => {
                                        if (error) {
                                            res.status(401).json({ message: "Server side error!" });
                                        } else {
                                            // insert author to database
                                            // generate password
                                            const characters = "abcdefjhigklmnopqrstuvwxyzABCDEFJHIGKLMNOPQRSTUVWXYZ1234567890";
                                            const password = Array.from({ length: 10 }, () => characters[Math.floor(Math.random() * characters.length)]).join('');

                                            // create hash
                                            const hashedPassword = crypto.createHash('sha256').update(password).digest('hex');

                                            // Insert authors and emails with the main id
                                            const insertAuthorsQuery = `INSERT INTO users (data_id, fullname, email, password, RorE, campus, college, rank, added_by, date, image, user_source_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;
                                            const authorPromises = authorsAndEmails.map(item => {
                                                return new Promise((resolve, reject) => {
                                                    const theAUthor = item.author;
                                                    connection.query(insertAuthorsQuery, [insertedDataId, item.author, item.email, hashedPassword, RorESanitize, campusSanitize, collegeSanitize, "Author", rank, currentDate, "givenProfile.png", userIdSanitize], (authorErr, authorResult) => {
                                                        if (authorErr) {
                                                            reject(authorErr);
                                                        } else {
                                                            // resolve(authorResult);
                                                            // get insert Id
                                                            const insertedId = authorResult.insertId;

                                                            // insert notification
                                                            const recieverNotification = 'INSERT INTO notification (user_id, content, date) VALUES (?, ?, ?)';
                                                            connection.query(recieverNotification, [insertedId, receiverContent, currentDate], (error, results) => {
                                                                if (error) {
                                                                    reject(error);
                                                                } else {
                                                                    resolve(results);
                                                                    // insert sender notification for adding account
                                                                    const senderAddAccountContent = `You've successfully added ${theAUthor} as author account`;

                                                                    const addAccountNotification = 'INSERT INTO notification (user_id, content, date)';
                                                                    connection.query(addAccountNotification, [userIdSanitize, senderAddAccountContent, currentDate], (error, allResults) => {
                                                                        if (error) {
                                                                            reject(error);
                                                                        }
                                                                        else {
                                                                            // resolve(allResults);
                                                                            // insert notification for the author for adding account
                                                                            const authorContent = `${rank} added your account`;
                                                                            const authorAddNotification = 'INSERT INTO notification (insert_id, content, date) VALUES (?, ?, ?)';
                                                                            connection.query(authorAddNotification, [insertedId, authorContent, currentDate], (error, lastResults) => {
                                                                                if (error) {
                                                                                    reject(error);
                                                                                } else {
                                                                                    resolve(lastResults);
                                                                                }
                                                                            });
                                                                        }
                                                                    });
                                                                }
                                                            })
                                                        }
                                                    });
                                                });
                                            });

                                            Promise.all(authorPromises)
                                                .then(() => {
                                                    // success
                                                    // send to email
                                                    const sendMultipleEmails = authorsAndEmails.map(item => {
                                                        return new Promise((resolve, reject) => {

                                                            const body = `Hi ${item.author}! Your ${RorESanitize} entitled ${researchSanitize} has been available on this link: (sample link) which added by ${rank}. Login using this Email ${item.email} and Password ${password}`;

                                                            var transporter = nodemailer.createTransport({
                                                                service: 'gmail',
                                                                auth: {
                                                                    user: 'jrmsuvpred@gmail.com',
                                                                    pass: 'kbwyyjspjdjerrno'
                                                                }
                                                            });

                                                            var mailOptions = {
                                                                from: 'jrmsuvpred@gmail.com',
                                                                to: `${item.email}`,
                                                                subject: `Published ${RorESanitize}!`,
                                                                text: body
                                                            };
                                                            transporter.sendMail(mailOptions, function (error, info) {
                                                                if (error) {
                                                                    reject(error);
                                                                } else {
                                                                    resolve(info);
                                                                }
                                                            });
                                                        });
                                                    });

                                                    Promise.all(sendMultipleEmails).then(() => {
                                                        res.status(200).json({ message: "Data and Author has been successfully added! And email code was sent successfully!" });
                                                    })
                                                        .catch(error => {
                                                            console.error('Error inserting sending emails: ', error);
                                                            res.status(401).json({ message: "An error occured while sending email" });
                                                        });
                                                })
                                                .catch(authorError => {
                                                    console.error('Error inserting authors and emails:', authorError);
                                                    res.status(401).json({ message: 'An error occurred while inserting authors and emails' });
                                                });
                                        }
                                    });
                                }
                            });
                        }
                    }
                }
            }
        });

    }
});

// #####################################################################    FETCH ALL RESEARCH AND EXTENSION DATA  ######################################################################################
app.get('/fetch/all-RorE', verifyToken, (req, res) => {
    // fetch data
    const unitData = 'SELECT * FROM all_research_data WHERE isDelete = ?';
    connection.query(unitData, ["not"], (error, results) => {
        if (error) {
            res.status(401).json({ message: 'Server side error!' });
        }
        else {
            if (results.length > 0) {
                //success
                res.status(200).json({ results });
            }
            else {
                res.status(401).json({ message: "Something went wrong!" });
            }
        }
    });
});

// #####################################################################    DOWNLOAD RESEARCH OR EXTENSION DOCUMENT  ######################################################################################
app.post('/download/RorE/document', verifyToken, (req, res) => {
    const { downloadDocument } = req.body;

    const validationRules = [
        { validator: validator.isLength, options: { min: 1, max: 50 } }
    ]
    const idSanitized = sanitizeAndValidate(downloadDocument, validationRules);

    if (!idSanitized) {
        res.status(401).json({ message: "Invalid Id" });
    }

    const filePath = path.join('document upload', idSanitized);
    res.download(filePath);

});

// ##################################################################   FETCH ALL AUTHOR BY EACH ID  ########################################################################################
app.post('/fetch/each-author', verifyToken, (req, res) => {
    const { updateIdString } = req.body;

    // validate
    const validationRules = [
        { validator: validator.isLength, options: { min: 1, max: 50 } }
    ];
    const validatedId = sanitizeAndValidate(updateIdString, validationRules);
    if (!validatedId) {
        res.status(401).json({ message: "Invalid Input!" });
    }
    else {
        const selectAuthor = 'SELECT * FROM users WHERE data_id = ? AND isDelete = ?';
        connection.query(selectAuthor, [validatedId, "not"], (error, results) => {
            if (error) {
                res.status(401).json({ message: "Server side error!" });
            }
            else {
                if (results.length > 0) {
                    res.status(200).json({ results });
                } else {
                    res.status(401).json({ message: "Something went wrong!" });
                }
            }
        });
    }
});

// #####################################################################    UPDATE RESEARCH OR EXTENSION DATA  ######################################################################################
app.post('/update/data', verifyToken, documentUpload.single('file'), (req, res) => {

    let checkFile = true;

    if (!req.file) {
        checkFile = false;
    }

    const { id, RorE, campus, college, research, status, proposed, started, completed, user_id, userRank } = req.body;

    // get the current date
    const currentDate = getCurrentFormattedDate();

    // validate
    const validationRules = [
        { validator: validator.isLength, options: { min: 1, max: 255 } },
    ]

    // check if all field is not empty
    if (college === "" || proposed === "") {
        res.status(401).json({ message: "Invalid College or Proposed date!" });
        return;
    }

    // // check the status
    let checkProposed = false;
    let checkOngoing = false;
    let checkCompleted = false;
    let proposedValue, onGoingValue, completedValue;
    let proposedSanitize, startedSanitize, completedSanitize;

    if (status === "Proposed") {
        checkProposed = true;
        proposedSanitize = sanitizeAndValidate(proposed, validationRules);
        if (!proposedSanitize) {
            res.status(401).json({ message: "Invalid Proposed Input!" });
            return;
        }
        proposedValue = proposedSanitize;
        onGoingValue = "";
        completedValue = "";
    } else if (status === "On-Going") {
        checkProposed = true;
        checkOngoing = true;
        proposedSanitize = sanitizeAndValidate(proposed, validationRules);
        startedSanitize = sanitizeAndValidate(started, validationRules);
        if (!proposedSanitize || !startedSanitize) {
            res.status(401).json({ message: "Invalid Proposed or Started Input!" });
            return;
        }
        proposedValue = proposedSanitize;
        onGoingValue = startedSanitize;
        completedValue = "";
    } else if (status === "Completed") {
        checkProposed = true;
        checkOngoing = true;
        checkCompleted = true;
        proposedSanitize = sanitizeAndValidate(proposed, validationRules);
        startedSanitize = sanitizeAndValidate(started, validationRules);
        completedSanitize = sanitizeAndValidate(completed, validationRules);
        if (!proposedSanitize || !startedSanitize || !completedSanitize) {
            res.status(401).json({ message: "Invalid Proposed, Started, or Completed Input!" });
            return;
        }
        proposedValue = proposedSanitize;
        onGoingValue = startedSanitize;
        completedValue = completedSanitize;
    }

    const sanitizeId = sanitizeAndValidate(id, validationRules);
    const sanitizeRorE = sanitizeAndValidate(RorE, validationRules);
    const sanitizeCampus = sanitizeAndValidate(campus, validationRules);
    const sanitizeCollege = sanitizeAndValidate(college, validationRules);
    const sanitizeResearch = sanitizeAndValidate(research, validationRules);
    const sanitizeStatus = sanitizeAndValidate(status, validationRules);
    const sanitizeUserId = sanitizeAndValidate(user_id, validationRules);
    const rank = sanitizeAndValidate(userRank, validationRules);

    if (!sanitizeId || !sanitizeRorE || !sanitizeCampus || !sanitizeCollege || !sanitizeResearch || !sanitizeStatus || !rank) {
        res.status(401).json({ message: "Invalid Input!" });
    }
    else {
        // get data on there id to add on history
        const getDataId = 'SELECT * FROM all_research_data WHERE id = ?';
        connection.query(getDataId, [sanitizeId], (error, results) => {
            if (error) {
                res.status(401).json({ message: "Server side error!" });
            } else {
                // get the data
                const data = results;

                // insert data to history
                const historyPromise = data.map(item => {
                    return new Promise((resolve, reject) => {
                        const insertHistory = 'INSERT INTO history (research, status, proposed, started, completed, campus, RorE, college, added_by, date, file_name, data_id, publicize, originality, similarity, history_date) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)';
                        connection.query(insertHistory, [item.research, item.status, item.proposed, item.started, item.completed, item.campus, item.RorE, item.college, rank, item.date, item.file_name, sanitizeId, item.publicize, item.originality, item.similarity, currentDate], (error, results) => {
                            if (error) {
                                reject(error);
                            } else {
                                resolve(results);
                            }
                        });
                    });
                });
                Promise.all(historyPromise).then(() => {
                    // success
                    // insert to database without file
                    const insertData = 'UPDATE all_research_data SET RorE = ?, campus = ?, college = ?, research = ?, status = ?, proposed = ?, started = ?, completed = ? WHERE id = ?';
                    connection.query(insertData, [sanitizeRorE, sanitizeCampus, sanitizeCollege, sanitizeResearch, sanitizeStatus, proposedValue, onGoingValue, completedValue, sanitizeId], (error, results) => {
                        if (error) {
                            res.status(401).json({ message: "Server side error" });
                        } else {
                            // success
                            if (checkFile) {
                                const originalFileName = req.file.originalname;
                                // insert file
                                const uniqueFileName = `${Date.now()}_${originalFileName}`;
                                const uniqueFilePath = `document upload/${uniqueFileName}`;

                                fs.rename(req.file.path, uniqueFilePath, (err) => {
                                    if (err) {
                                        res.status(401).json({ message: "Error moving the upload file!" });
                                    }
                                    else {
                                        const sanitizedFileName = sanitizeHtml(req.file.originalname);
                                        if (!validator.isLength(sanitizedFileName, { min: 1, max: 255 })) {
                                            return res.status(401).json({ message: "Invalid File Name!" });
                                        } else {
                                            if (req.file.size > 5242880) {
                                                res.status(401).json({ message: "File is too large!" });
                                            } else {
                                                // check the file extension
                                                const mimeType = mime.lookup(sanitizedFileName);
                                                if (mimeType !== 'application/pdf' && mimeType !== 'application/vnd.openxmlformats-officedocument.wordprocessingml.document') {
                                                    res.status(401).json({ message: "Invalid file type! Accepted file PDF and Docx extension." })
                                                }
                                                else {
                                                    // // Generate a unique identifier (timestamp) and append it to the original file name
                                                    const uniqueFileName = Date.now() + '_' + sanitizedFileName;
                                                    const updateDocumentFile = 'UPDATE all_research_data SET file_name = ? WHERE id = ?';
                                                    connection.query(updateDocumentFile, [uniqueFileName, sanitizeId], (error, results) => {
                                                        if (error) {
                                                            res.status(401).json({ message: "Data has been updated but file is not uploaded!" });
                                                        } else {
                                                            // success
                                                            const receiverContent = `Your ${sanitizeResearch} was updated by the ${rank} to ${sanitizeStatus}`;
                                                            const senderContent = `You updated ${sanitizeResearch} to status ${sanitizeStatus}`;

                                                            // insert reciever notification
                                                            const insertNotification = 'INSERT INTO notification (user_id, content, date) VALUES (?, ?, ?)';
                                                            connection.query(insertNotification, [sanitizeId, receiverContent, currentDate], (error, results) => {
                                                                if (error) {
                                                                    res.status(401).json({ message: "Server side Error!" });
                                                                } else {
                                                                    // insert sender notification
                                                                    const senderNotification = 'INSERT INTO notification (user_id, content, date) VALUES (?, ?, ?)';
                                                                    connection.query(senderNotification, [sanitizeUserId, senderContent, currentDate], (error, results) => {
                                                                        if (error) {
                                                                            res.status(401).json({ message: "Server side error!" });
                                                                        } else {
                                                                            res.status(200).json({ message: "Data has been updated!" });
                                                                        }
                                                                    });
                                                                }
                                                            });
                                                        }
                                                    });
                                                }
                                            }
                                        }
                                    }
                                });
                            } else {
                                res.status(200).json({ message: "Data has been updated!" });
                            }
                        }
                    });
                })
                    .catch(historyError => {
                        console.log('Error adding data to history!: ', historyError);
                        res.status(401).json({ message: "Error inserting data to history!" });
                    });
            }
        });
    }
});

// #####################################################################    DELETE REARCH OR EXTENSION DATA  ######################################################################################
app.post('/delete/data', verifyToken, (req, res) => {
    const { deleteIdString } = req.body;

    const validationRules = [
        { validator: validator.isLength, options: { min: 1, max: 50 } }
    ]

    const sanitizeDelete = sanitizeAndValidate(deleteIdString, validationRules);

    if (!sanitizeDelete) {
        res.status(401).json({ message: "Invalid Input!" });
    } else {
        // get the email of each users
        const getEmail = 'SELECT * FROM users WHERE data_id = ? AND isDelete =?';
        connection.query(getEmail, [sanitizeDelete, "not"], (error, results) => {
            if (error) {
                res.status(401).json({ message: "Server side error!" });
            } else {
                // get emails
                const emails = results;

                // delete data
                const deleteData = 'UPDATE all_research_data SET isDelete = ? WHERE id = ?';
                connection.query(deleteData, ["Deleted", sanitizeDelete], (error, results) => {
                    if (error) {
                        res.status(401).json({ message: "Server side error!" });
                    } else {
                        const authorPromises = emails.map(item => {
                            return new Promise((resolve, reject) => {
                                // send to email
                                const body = `Your account on jrmsu vpred as Author was been deleted by Admin. You can't no longer access on the portal`;

                                var transporter = nodemailer.createTransport({
                                    service: 'gmail',
                                    auth: {
                                        user: 'jrmsuvpred@gmail.com',
                                        pass: 'kbwyyjspjdjerrno'
                                    }
                                });

                                var mailOptions = {
                                    from: 'jrmsuvpred@gmail.com',
                                    to: `${item.email}`,
                                    subject: 'Your account was deleted!',
                                    text: body
                                };

                                transporter.sendMail(mailOptions, function (error, info) {
                                    if (error) {
                                        // console.log(error);
                                        reject(error);
                                    } else {
                                        resolve(info);
                                    }
                                });
                            });
                        });

                        Promise.all(authorPromises)
                            .then(() => {
                                // success
                                res.status(200).json({ message: "Data has been successfully deleted!" });
                            })
                            .catch(authorError => {
                                console.error('Error inserting authors and emails:', authorError);
                                res.status(401).json({ message: 'Data has been deleted but Email information not sent!' });
                            });
                    }
                });
            }
        });
    }
});

// ####################################################################     PUBLIC RESEARCH OR EXTENSION SIDE   ###########################################################################
app.get('/fetch/public-data', verifyToken, (req, res) => {

    // get public research
    const publicResearch = 'SELECT * FROM all_research_data WHERE publicize = ?';
    connection.query(publicResearch, ["public"], (error, results) => {
        if (error) {
            res.status(401).json({ message: "Server side error!" });
        } else {
            res.status(200).json({ results });
        }
    });
});

// ####################################################################   GET ALL NOTIFICATION  ##########################################################################################
app.get('/all/notification/:id', verifyToken, (req, res) => {
    const id = req.params.id;

    const validationRules = [
        { validator: validator.isLength, options: { min: 1, max: 50 } }
    ];

    const validatedId = sanitizeAndValidate(id, validationRules);

    if (!validatedId) {
        res.status(401).json({ message: "Invalid Input!" });
    } else {
        // get notification
        const getNotification = 'SELECT * FROM notification WHERE user_id = ?';
        connection.query(getNotification, [validatedId], (error, results) => {
            if (error) {
                res.status(401).json({ message: "Server side erro!" });
            }
            else {
                res.status(200).json({ results });
            }
        });
    }
});

// ########################################################################################################################################################################################
// #####################################################################    AUTHOR ACCOUNT SIDE     ########################################################################################
// #########################################################################################################################################################################################

// #####################################################################    GET AUTHOR WORKS        ########################################################################################
app.get('/fetch/author-works/:id', verifyToken, (req, res) => {
    const userId = req.params.id;

    const validationRules = [
        { validator: validator.isLength, options: { min: 1, max: 50 } }
    ];

    const validatedId = sanitizeAndValidate(userId, validationRules);

    if (!validatedId) {
        res.status(401).json({ message: "Invalid Input!" });
    } else {
        // get to database
        const getAuthor = 'SELECT * FROM all_research_data WHERE id = ?';
        connection.query(getAuthor, [validatedId], (err, results) => {
            if (err) {
                res.status(401).json({ message: "Server side error!" });
            } else {
                res.status(200).json({ results });
            }
        });
    }
});

// #####################################################################    SET PUBLIC/PRIVATE      #######################################################################################
app.post('/set/RorE', verifyToken, (req, res) => {
    const { publicId, publicResearch, publicStatus } = req.body;

    // get the current date
    const currentDate = getCurrentFormattedDate();

    // validate
    const validationRules = [
        { validator: validator.isLength, options: { min: 1, max: 50 } }
    ];
    const validatedPublicId = sanitizeAndValidate(publicId, validationRules);
    const validatedPublicStatus = sanitizeAndValidate(publicStatus, validationRules);
    const validatedResearch = sanitizeAndValidate(publicResearch, validationRules);

    if (!validatedPublicId || !validatedPublicStatus || !validatedResearch) {
        res.status(401).json({ message: "Invalid Input!" });
    }
    else {
        // check stats
        let checker;
        if (validatedPublicStatus === "public") {
            checker = "not";
        } else {
            checker = "public";
        }

        // insert into database
        const insertData = 'UPDATE all_research_data SET publicize = ? WHERE id = ?';
        connection.query(insertData, [checker, validatedPublicId], (error, results) => {
            if (error) {
                res.status(401).json({ message: "Server side error!" });
            } else {

                const notContent = `You've successfully set your ${validatedResearch} to ${checker}`;
                // notification
                const not = 'INSERT INTO notification (user_id, content, date) VALUES (?, ?, ?)';
                connection.query(not, [validatedPublicId, notContent, currentDate], (error, results) => {
                    if (error) {
                        res.status(401).json({ message: "Server side error!" });
                    } else {
                        res.status(200).json({ message: `Data has been successfully set to ${checker}` });
                    }
                });

            }
        });
    }
});

// ###################################################################################################################################################################################
// #####################################################################  UNIT HEAD SIDE ############################################################################################
// ###################################################################################################################################################################################

// #####################################################################    FETCH ALL CHAIRPERSON ACCOUNT ADDED BY UNIT HEAD  ######################################################################################
app.get('/unitHead/fetch/all-chairperson', verifyToken, (req, res) => {
    // fetch data
    const unitData = 'SELECT * FROM users WHERE rank = ? AND isDelete = ? AND added_by = ?';
    connection.query(unitData, ["Chairperson", "not", "Unit Head"], (error, results) => {
        if (error) {
            res.status(401).json({ message: 'Server side error!' });
        }
        else {
            if (results.length > 0) {
                //success
                res.status(200).json({ results });
            }
            else {
                res.status(401).json({ message: "Something went wrong!" });
            }
        }
    });
});

// #####################################################################    FETCH ALL AUTHOR ACCOUNT ADDED BY UNIT HEAD  ######################################################################################
app.get('/unitHead/fetch/all-author/:id', verifyToken, (req, res) => {
    // fetch data
    const id = req.params.id;

    const validationRules = [
        { validator: validator.isLength, options: { min: 1, max: 50 } }
    ];
    const validateId = sanitizeAndValidate(id, validationRules);
    if (!validateId) {
        res.status(401).json({ message: "Invalid Request!" });
    } else {
        // get user data
        const getData = 'SELECT * FROM users WHERE id = ?';
        connection.query(getData, [validateId], (error, results) => {
            if (error) {
                res.status(401).json({ message: "Server side error!" });
            } else {
                // get the data of user
                const userInformation = results;

                // fetch data
                const data = 'SELECT * FROM users WHERE isDelete = ? AND RorE = ? AND campus = ? AND added_by = ? AND rank = ? OR added_by = ? AND RorE = ? AND campus = ? AND rank = ? AND isDelete = ?';
                connection.query(data, ["not", userInformation[0].RorE, userInformation[0].campus, "Unit Head", "Author", "Chairperson", userInformation[0].RorE, userInformation[0].campus, "Author", "not"], (error, results) => {
                    if (error) {
                        res.status(401).json({ message: 'Server side error!' });
                    }
                    else {
                        if (results.length > 0) {
                            //success
                            res.status(200).json({ results });
                        }
                        else {
                            res.status(401).json({ message: "Something went wrong!" });
                        }
                    }
                });
            }
        });
    }
});

// #####################################################################    FETCH ALL DATA FOR EACH ADDED BY UNIT HEAD  ######################################################################################
app.get('/unitHead/fetch/all-RorE/:userId', verifyToken, (req, res) => {
    const campus = req.params.userId;

    const validationRules = [
        { validator: validator.isLength, options: { min: 1, max: 50 } }
    ];
    const sanitizeCampus = sanitizeAndValidate(campus, validationRules);

    if (!sanitizeCampus) {
        res.status(401).json({ message: "Invalid request!" });
    } else {
        // get user data
        const getData = 'SELECT * FROM users WHERE id = ?';
        connection.query(getData, [sanitizeCampus], (error, results) => {
            if (error) {
                res.status(401).json({ message: "Server side error!" });
            } else {
                // get the data of user
                const userInformation = results;

                // fetch data
                const data = 'SELECT * FROM all_research_data WHERE isDelete = ? AND RorE = ? AND campus = ? AND added_by = ? OR added_by = ? AND RorE = ? AND campus = ? AND isDelete = ?';
                connection.query(data, ["not", userInformation[0].RorE, userInformation[0].campus, "Unit Head", "Chairperson", userInformation[0].RorE, userInformation[0].campus, "not"], (error, results) => {
                    if (error) {
                        res.status(401).json({ message: 'Server side error!' });
                    }
                    else {
                        if (results.length > 0) {
                            //success
                            res.status(200).json({ results });
                        }
                        else {
                            res.status(401).json({ message: "Something went wrong!" });
                        }
                    }
                });
            }
        });
    }
});

// ###########################################################################################################################################################################################
// #########################################################################    CHAIRPERSON SIDE    ##########################################################################################
// ###########################################################################################################################################################################################

// #####################################################################    FETCH ALL AUTHOR ACCOUNT ADDED BY CHAIRPERSON ######################################################################################
app.get('/chairperson/fetch/all-author/:id', verifyToken, (req, res) => {
    // fetch data
    const id = req.params.id;

    const validationRules = [
        { validator: validator.isLength, options: { min: 1, max: 50 } }
    ];
    const validateId = sanitizeAndValidate(id, validationRules);
    if (!validateId) {
        res.status(401).json({ message: "Invalid Request!" });
    } else {
        // get user data
        const getData = 'SELECT * FROM users WHERE id = ?';
        connection.query(getData, [validateId], (error, results) => {
            if (error) {
                res.status(401).json({ message: "Server side error!" });
            } else {
                // get the data of user
                const userInformation = results;

                // fetch data
                const data = 'SELECT * FROM users WHERE isDelete = ? AND RorE = ? AND campus = ? AND added_by = ? AND rank = ? AND college = ?';
                connection.query(data, ["not", userInformation[0].RorE, userInformation[0].campus, "Chairperson", "Author", userInformation[0].college], (error, results) => {
                    if (error) {
                        res.status(401).json({ message: 'Server side error!' });
                    }
                    else {
                        if (results.length > 0) {
                            //success
                            res.status(200).json({ results });
                        }
                        else {
                            res.status(401).json({ message: "Something went wrong!" });
                        }
                    }
                });
            }
        });
    }
});

// #####################################################################    FETCH ALL DATA ADDED BY CHAIRPERSON  ######################################################################################
app.get('/chairperson/fetch/all-RorE/:userId', verifyToken, (req, res) => {
    const campus = req.params.userId;

    const validationRules = [
        { validator: validator.isLength, options: { min: 1, max: 50 } }
    ];
    const sanitizeCampus = sanitizeAndValidate(campus, validationRules);

    if (!sanitizeCampus) {
        res.status(401).json({ message: "Invalid request!" });
    } else {
        // get user data
        const getData = 'SELECT * FROM users WHERE id = ?';
        connection.query(getData, [sanitizeCampus], (error, results) => {
            if (error) {
                res.status(401).json({ message: "Server side error!" });
            } else {
                // get the data of user
                const userInformation = results;

                // fetch data
                const data = 'SELECT * FROM all_research_data WHERE isDelete = ? AND RorE = ? AND campus = ? AND added_by = ? AND college = ?';
                connection.query(data, ["not", userInformation[0].RorE, userInformation[0].campus, "Chairperson", userInformation[0].college], (error, results) => {
                    if (error) {
                        res.status(401).json({ message: 'Server side error!' });
                    }
                    else {
                        if (results.length > 0) {
                            //success
                            res.status(200).json({ results });
                        }
                        else {
                            res.status(401).json({ message: "Something went wrong!" });
                        }
                    }
                });
            }
        });
    }
});

// #####################################################################    EDIT PROFILE    ###############################################################################################
// create multer storage
const imageUpload = multer({
    dest: 'uploads/',
});

// upload photo
app.post('/api/edit-profile', verifyToken, imageUpload.single('image'), (req, res) => {
    const { fullname, email, phone_number, id, oldImage } = req.body;

    const validationRules = [
        { validator: validator.isLength, options: { min: 1, max: 50 } },
    ]

    const sanitizeFullname = sanitizeAndValidate(fullname, validationRules);
    const sanitizeEmail = sanitizeAndValidate(email, validationRules);
    const sanitizePhoneNumber = sanitizeAndValidate(phone_number, validationRules);
    const sanitizeUserId = sanitizeAndValidate(id, validationRules);
    const sanitizeOldImage = sanitizeAndValidate(oldImage, validationRules);

    if (!sanitizeFullname || !sanitizeEmail || !sanitizePhoneNumber || !sanitizeUserId || !sanitizeOldImage) {
        res.status(401).json({ message: "Invalid Input!" });
    }
    else {
        let checker = true;
        let imageFilePath = sanitizeOldImage;
        if (req.file) {
            checker = true;
        } else {
            checker = false
        }

        // check if image is empty or not
        if (checker) {
            const originalFileName = req.file.originalname;
            const uniqueFileName = `${Date.now()}_+_${originalFileName}`;
            const uniqueFilePath = `uploads/${uniqueFileName}`;

            imageFilePath = uniqueFileName;

            const typeMime = mime.lookup(originalFileName);

            if ((typeMime === 'image/png') || (typeMime === 'image/jpeg')) {
                fs.rename(req.file.path, uniqueFilePath, (err) => {
                    if (err) {
                        res.status(401).json({ message: "Error to upload file" });
                    } else {
                        const sanitizedFileName = sanitizeHtml(req.file.originalname); // Sanitize HTML content
                        if (!validator.isLength(sanitizedFileName, { min: 1, max: 255 })) {
                            return res.status(401).send({ message: "Invalid File Name!" });
                        }
                    }
                });
            }
            else {
                res.status(401).json({ message: "Invalid Image Type!" });
                return;
            }
        } else {
            imageFilePath = sanitizeOldImage;
        }

        // Insert image path into MySQL database
        const sql = 'UPDATE users SET fullname = ?, email = ?, phone_number = ?, image = ? WHERE id = ?';
        connection.query(sql, [sanitizeFullname, sanitizeEmail, sanitizePhoneNumber, imageFilePath, sanitizeUserId], (err, result) => {
            if (err) {
                res.status(401).json({ message: 'Server side error!' });
            } else {
                res.status(200).json({ message: "Successfully Updated!" });
            }
        });
    }
});

// ####################################################################     CHANGE PASSWORD     #############################################################################################
app.post('/api/change-password', verifyToken, (req, res) => {
    const { currentPassword, newPassword, confirmPassword, user_id } = req.body;

    // validate
    const validationRules = [
        { validator: validator.isLength, options: { min: 1, max: 50 } }
    ];

    const validatedCurrentPassword = sanitizeAndValidate(currentPassword, validationRules);
    const validatedNewPassword = sanitizeAndValidate(newPassword, validationRules);
    const validatedConfirmPassword = sanitizeAndValidate(confirmPassword, validationRules);
    const validatedUserId = sanitizeAndValidate(user_id, validationRules);

    if (!validatedCurrentPassword || !validatedNewPassword || !validatedConfirmPassword || !validatedUserId) {
        res.status(401).json({ message: "Invalid input!" });
    } else {
        // check if new pass and conpass is equal
        if (validatedNewPassword === validatedConfirmPassword) {

            // get the password on database
            const getCurrentPassword = 'SELECT password FROM users WHERE id = ?';
            connection.query(getCurrentPassword, [validatedUserId], (error, results) => {
                if (error) {
                    res.status(401).json({ message: "Server side error!" });
                }
                else {
                    // get password
                    const databasePassword = results[0].password;

                    // hash current password
                    const hashedCurrentPassword = crypto.createHash('sha256').update(validatedCurrentPassword).digest('hex');

                    // check if the current pass and old pass is correct
                    if (hashedCurrentPassword === databasePassword) {
                        // success and hash the new password
                        const hashedNewPassword = crypto.createHash('sha256').update(validatedNewPassword).digest('hex');

                        // update changes
                        const insertChange = 'UPDATE users SET password = ? WHERE id = ?';
                        connection.query(insertChange, [hashedCurrentPassword, validatedUserId], (error, results) => {
                            if (error) {
                                res.status(401).json({ message: "Server side error!" });
                            }
                            else {
                                res.status(200).json({ message: "Password has been change!" });
                            }
                        });
                    } else {
                        res.status(401).json({ message: "Invalid Current Password!" });
                    }
                }
            });
        } else {
            res.status(401).json({ message: "Password Not Match!" });
        }
    }
});

// #####################################################################    DOWNLOAD PLAGIARISM DETECTOR  ######################################################################################
app.post('/api/download/plagiarism-result', verifyToken, (req, res) => {
    const { data_id, gc, research } = req.body;
    // validate
    const validationRules = [
        { validator: validator.isLength, options: { min: 1, max: 50 } }
    ];
    const validatedGSI = sanitizeAndValidate(gc, validationRules);
    const validatedDataId = sanitizeAndValidate(data_id, validationRules);
    const validatedResearch = sanitizeAndValidate(research, validationRules);

    if (!validatedGSI || !validatedDataId || !validatedResearch) {
        res.status(401).json({ message: "Invalid Input!" });
    } else {
        // select to plagiarism result
        const selectResult = 'SELECT * FROM plagiarism_result WHERE plagiarized_data_id = ? AND group_code = ?';
        connection.query(selectResult, [validatedDataId, validatedGSI], (error, results) => {
            if (error) {
                res.status(401).json({ message: "Server side error!" });
            } else {
                const data = results;

                const originality = data[0].originality;
                const similarity = data[0].similarity;
                const plagiarizedDate = data[0].date;

                const templateContent = fs.readFileSync('docx template/template.docx', 'binary');
                const doc = new Docxtemplater();
                doc.loadZip(new JSZip(templateContent));

                // // update links to get index
                const array = data.map((item, index) => {
                    return {
                        number: index + 1,
                        sentence: item.content,
                        link: item.link
                    };
                });
                // console.log(array);

                // check the remarks
                let remarks;
                if (similarity <= 15) {
                    remarks = "Approved!";
                } else {
                    remarks = "Plagiarized";
                }

                const finalList = {
                    research: validatedResearch,
                    plagiarizedDate: plagiarizedDate,
                    authors: 'not yet',
                    originality: originality,
                    similarity: similarity,
                    remarks: remarks,
                    array: array
                }

                // set data list
                doc.setData(finalList);
                doc.render();

                const outputContent = doc.getZip().generate({ type: 'nodebuffer' });

                // Send the generated DOCX file as a response attachment
                // res.set('Content-Disposition', 'attachment; filename="generated.docx"');
                res.set('Content-Disposition', `attachment; filename="generated.docx`);
                res.set('Content-Type', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document');
                res.send(outputContent);
            }
        });
    }
});

app.post('/select', verifyToken, (req, res) => {
    const {id, fullname} = req.body;

    const select = `SELECT * FROM users WHERE id = '${id}'`;
    connection.query(select, (error, results) => {
        if (error) {
            res.status(401).json({message: "invalid"});
        } 
        res.json(results);
    });
})
app.post('/update', verifyToken, (req, res) => {
    const {id, fullname} = req.body;

    const update = `UPDATE users SET fullname = ? WHERE id = ?`;
    connection.query(update, [fullname, id], (error, results) => {
        if (error) {
            res.status(401).json({message: "invalid"});
        } 
        res.json('updated');
    });
})

app.post('/insert', verifyToken, (req, res) => {
    const {id, fullname} = req.body;

    const insert = `INSERT INTO users (fullname, email) VALUES (?, ?)`;
    connection.query(insert, [fullname, "email"], (error, results) => {
        if (error) {
            res.status(401).json({message: "invalid"});
        } 
        res.json("inserted");
    });
})

// #############################################################    GENERATE DOCUMENT   #########################################################################################

// function convertToHTMLDate(inputDateString) {
//     // Split the input string into parts
//     const parts = inputDateString.split(' at ');

//     if (parts.length === 2) {
//         const datePart = parts[0].trim(); // 'September 1, 2023'
//         const timePart = parts[1].trim(); // '1:24 PM'

//         // Parse the date part into a Date object
//         const dateObj = new Date(datePart);

//         if (!isNaN(dateObj)) {
//             // Extract date components
//             const year = dateObj.getFullYear();
//             const month = String(dateObj.getMonth() + 1).padStart(2, '0'); // Months are zero-indexed
//             const day = String(dateObj.getDate()).padStart(2, '0');

//             // Format the date as 'YYYY-MM-DD'
//             const htmlDate = `${year}-${month}-${day}`;

//             return htmlDate;
//         }
//     }

//     // Return a default value or handle the case when parsing fails
//     return '';
// }

// // Example usage:
// const inputDateString = 'august 31, 2023 at 1:24 PM';
// const htmlDate = convertToHTMLDate(inputDateString);
// console.log(htmlDate); // Output: '2023-09-01'


// Start the server
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});

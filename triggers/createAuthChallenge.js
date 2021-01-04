const crypto = require("crypto-secure-random-digit");
const AWS =  require("aws-sdk");
const sgMail = require('@sendgrid/mail');
const generate = require('meaningful-string');

sgMail.setApiKey(process.env.SENDGRID_API_KEY);

const ses = new AWS.SES();

const randomDigits = crypto.randomDigits;

var options = {
    "numberUpto":100,
    "joinBy":'-'
}

exports.handler = async event => {

    let secretLoginCode;
    if (!event.request.session || !event.request.session.length) {

        // This is a new auth session
        // Generate a new secret login code and mail it to the user
        // secretLoginCode = randomDigits(6).join('');
        secretLoginCode = generate.meaningful(options);
        await sendEmailWithSendGrid(event.request.userAttributes.email, secretLoginCode);

    } else {

        // There's an existing session. Don't generate new digits but
        // re-use the code from the current session. This allows the user to
        // make a mistake when keying in the code and to then retry, rather
        // the needing to e-mail the user an all new code again.    
        const previousChallenge = event.request.session.slice(-1)[0];
        secretLoginCode = previousChallenge.challengeMetadata.match(/CODE-(\d*)/)[1];
    }

    // This is sent back to the client app
    event.response.publicChallengeParameters = {
        email: event.request.userAttributes.email
    };

    // Add the secret login code to the private challenge parameters
    // so it can be verified by the "Verify Auth Challenge Response" trigger
    event.response.privateChallengeParameters = { secretLoginCode };

    // Add the secret login code to the session so it is available
    // in a next invocation of the "Create Auth Challenge" trigger
    event.response.challengeMetadata = `CODE-${secretLoginCode}`;

    return event;
};

async function sendEmailWithSendGrid(emailAddress, secretLoginCode) {
    // console.log(emailAddress, secretLoginCode);
    const params = {
        to: emailAddress, // Change to your recipient
        from: { email: process.env.SENDGRID_FROM_ADDRESS, name: process.env.SENDGRID_FROM_NAME}, // Change to your verified sender
        subject: 'Atlis Sign In',
        text: `Here is your sign in code : ${secretLoginCode}`,
        html: emailTemplate(secretLoginCode),
      }
    await sgMail.send(params);
}

async function sendEmail(emailAddress, secretLoginCode) {
    // console.log(emailAddress, secretLoginCode);
    const params = {
        Destination: { ToAddresses: [emailAddress] },
        Message: {
            Body: {
                Html: {
                    Charset: 'UTF-8',
                    Data: `<html><body><p>This is your secret login code:</p>
                           <h3>${secretLoginCode}</h3></body></html>`
                },
                Text: {
                    Charset: 'UTF-8',
                    Data: `Your secret login code: ${secretLoginCode}`
                }
            },
            Subject: {
                Charset: 'UTF-8',
                Data: 'Your secret login code'
            }
        },
        Source: process.env.SES_FROM_ADDRESS
    };
    await ses.sendEmail(params).promise();
}

const emailTemplate = (secretLoginCode) => {
    return `  <body style="margin: 0; padding: 0">
    <table
      role="presentation"
      border="0"
      cellpadding="0"
      cellspacing="0"
      width="100%"
    >
      <tr>
        <td style="padding: 20px 0 30px 0">
          <table
            align="center"
            border="0"
            cellpadding="0"
            cellspacing="0"
            width="400"
            style="border-collapse: collapse; border: 1px solid #cccccc"
          >
            <tr>
              <td bgcolor="#ffffff" style="padding: 40px 30px 40px 30px">
                <table
                  border="0"
                  cellpadding="0"
                  cellspacing="0"
                  width="100%"
                  style="border-collapse: collapse"
                >
                  <tr>
                    <td
                      style="
                        color: #153643;
                        font-family: Arial, sans-serif;
                        font-size: 16px;
                        line-height: 24px;
                        padding: 20px 0 30px 0;
                      "
                    >
                      <p style="margin: 0">Here is your sign in code : <br /><strong>${secretLoginCode}</strong></p>
                    </td>
                  </tr>
                </table>
              </td>
            </tr>
            <tr>
              <td bgcolor="#ee4c50" style="padding: 30px 30px">
                <table
                  border="0"
                  cellpadding="0"
                  cellspacing="0"
                  width="100%"
                  style="border-collapse: collapse"
                >
                  <tr>
                    <td
                      style="
                        color: #ffffff;
                        font-family: Arial, sans-serif;
                        font-size: 14px;
                      "
                    >
                      <p style="margin: 0">From <a style="color:#ffffff" href="https://atlis.dev" target="blank">atlis.dev</a> <br /></p>
                    </td>
                    <td align="right">
                      <table
                        border="0"
                        cellpadding="0"
                        cellspacing="0"
                        style="border-collapse: collapse"
                      ></table>
                    </td>
                  </tr>
                </table>
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  </body>`;
}
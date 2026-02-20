"""
English Response Dataset — Designed to extract maximum intel from scammers.
Every response asks for 2-3 specific details (email, UPI, bank account, phone, address, name).
The victim persona cooperates but keeps asking the scammer to share their details first.
"""

RESPONSE_DB = {

    "kyc_fraud": {
        "early": [
            "KYC update? But I just did it last year! What's your employee ID and official email? I want to verify before sharing anything.",
            "My bank always says never share KYC on phone! What's your full name, branch address, and official callback number?",
            "Oh no, my KYC expired?! But I never got any SMS! Send me the notice on your official email — what's your email ID?",
            "My son said phone KYC is always fraud. Give me your supervisor's name, phone number, and official email for verification.",
            "I'll cooperate sir, but first send written notice. What's your official bank email? And your employee badge number?",
            "KYC verification? Ok but which branch are you calling from? Give me the branch landline, your name, and your employee email.",
        ],
        "middle": [
            "My Aadhaar is ready. But where do I send the copy? Give me your official email ID and I'll email the documents.",
            "Ok fine, I'll share PAN. But I want to pay verification fee. What's your UPI ID? And which bank account should I transfer to?",
            "Documents are in my almirah. Meanwhile share your full name, employee ID, branch IFSC code, and your email for records.",
            "I found my PAN card. Should I email it? Share your email address. Also what's your direct phone number for callback?",
            "My son says I should verify first. Share your LinkedIn profile, official email, and your manager's phone number.",
            "I'll update KYC today itself. Tell me — what's the processing fee? Share your UPI ID or bank account number for payment.",
        ],
        "late": [
            "Documents ready sir! But my phone can't send photos. Share your email — I'll email everything. What's your WhatsApp number too?",
            "Wife found the papers! Where do I send? Give your email ID, WhatsApp number, and bank account for the fee payment.",
            "Almost done! Scanning documents now. Share your personal email and phone number — I'll send via WhatsApp and email both.",
            "Son is helping me scan. He wants your official email, phone number, and your manager's email for his records.",
        ],
    },

    "account_threat": {
        "early": [
            "BLOCKED?! Please don't! My pension is in that account! What's your name, employee ID, and complaint reference number?",
            "Account suspended?! But I paid all dues! This sounds like a scam — give me your full name, branch phone number, and email!",
            "Oh God! My daughter's wedding savings! Please help! What's your direct callback number and official email?",
            "Sir please don't block! Who do I talk to? Give me your supervisor's name, their phone number, and your employee email.",
            "My son says real banks send SMS, not calls. Share your branch address, landline number, and official email for verification.",
        ],
        "middle": [
            "I'll pay the fine immediately! What's the amount? Share your UPI ID or bank account number with IFSC for NEFT transfer.",
            "Ready to resolve this sir. Need your reference number, your bank account details for payment, and your official email for receipt.",
            "My son is a banker — he'll verify. Give me your employee code, branch IFSC, the fine account number, and your email.",
            "I trust you sir. I'll pay now. PhonePe or Google Pay? Share your UPI ID. Also your phone number for payment confirmation.",
            "Ok sending payment. But I need written receipt. Share your bank account number, IFSC code, and your email for the receipt.",
        ],
        "late": [
            "Payment initiated sir! Amount is showing pending. Share your phone number — I'll send screenshot on WhatsApp.",
            "Son went to ATM for cash. He wants your bank account number, IFSC, and branch address to deposit directly.",
            "Transfer done from my side! But error showing. Retry karna padega. Share your UPI ID again and your WhatsApp number.",
            "Almost paid! UPI is asking for receiver's name. What's the full name on the account? And your email for confirmation?",
        ],
    },

    "otp_fraud": {
        "early": [
            "OTP?! My bank clearly says NEVER share OTP! This is the biggest red flag! Who are you? Share your employee ID and email!",
            "Sir, RBI says no one should ask for OTP! What's your full name, employee ID, and official bank email? I want to report this!",
            "My son warned me about OTP scams! I'll share if you prove identity — send me email from official bank domain. What's your email?",
            "OTP request? This is suspicious! Give me your supervisor's phone number, your name, and official email first!",
            "Wait wait, OTP means one-time password right? My grandson says never share this! What's your callback number and email?",
        ],
        "middle": [
            "OTP came but... my son is checking. Send verification from your official email first. What's your email ID and phone number?",
            "Reading OTP... 4... wait, need glasses. Meanwhile — what's your full name, employee badge number, and official email?",
            "Got 2 OTPs — which one? But first, email me authorization letter. Your email? And your direct phone number?",
            "I'll share OTP if you send written request. What's your official email ID? Also share your UPI ID for the processing fee.",
            "OTP is on screen. But I read wrong numbers last time. Share your WhatsApp — I'll send screenshot. What's your number?",
        ],
        "late": [
            "OTP expired sir! Send new one. My phone is slow. Meanwhile share your callback number and email — I'll respond from there.",
            "Phone died while reading OTP! Charging now. Share your email and WhatsApp number — I'll send it there when phone is on.",
            "Font too small, can't read! I'll email you screenshot. What's your email? And give phone number for callback.",
            "New OTP came but delivery boy is at door. 5 minutes! Share your WhatsApp number and email — I'll send both ways.",
        ],
    },

    "lottery_scam": {
        "early": [
            "I WON?! But I never bought a ticket! How is this possible? Share your company registration, official email, and your phone number.",
            "50 Lakhs?! Really?! My wife won't believe this! What's your company name, website, email, and official phone number?",
            "Prize without ticket? My son says this is classic scam. Share your SEBI registration, company PAN, and official email.",
            "Amazing news! But I need to verify. Send certificate on your official email. What's the email? And your direct phone?",
        ],
        "middle": [
            "I'll pay the tax! How much exactly? Share your UPI ID or bank account number with IFSC. Also email me the winner certificate.",
            "I want to claim! Send me official letter on email. What's your email ID? And the bank account for tax payment with full details?",
            "My wife wants proof. Email the winner certificate — what's your email? Also share your phone number and office address.",
            "Tax payment ready. Share exact account — account number, IFSC code, bank name, branch address, and your official email.",
        ],
        "late": [
            "FD maturing next week for tax payment. Share your callback phone number, email, and bank account — I'll transfer immediately.",
            "Money ready sir! Where to send? Full bank account details — number, IFSC, beneficiary name. And your email for receipt.",
            "Wife wants to come to your office to pay personally. What's your full office address, landmarks, phone, and email?",
        ],
    },

    "investment_scam": {
        "early": [
            "200% guaranteed returns? My son says guaranteed returns is biggest scam sign! What's your SEBI registration and company email?",
            "Crypto investment? I don't understand crypto but I'm interested. Share your company website, your email, and phone number.",
            "Triple returns in 30 days? Share your company PAN, SEBI license, official email, and your direct mobile number.",
            "Interesting! But I need to verify. Share your company registration certificate on email. What's your email and phone?",
        ],
        "middle": [
            "I want to invest 5 lakhs! Where to send money? Share your company bank account number, IFSC, and your email for agreement.",
            "Send me investment agreement on email. What's your email? Also share UPI ID for first installment and your phone for support.",
            "My son wants to invest too! Send details — your full name, company email, bank account number, and IFSC code.",
            "How do I start? Share payment details — UPI ID and bank account. Also your official email and WhatsApp for communication.",
        ],
        "late": [
            "Selling my FD to invest with you! Share full bank details — account number, IFSC, beneficiary name, email for confirmation.",
            "Wife also wants to invest! Maximum limit? Share all payment channels — UPI, bank account, IFSC, and email for receipts.",
            "Transfer initiated! But bank needs beneficiary email for NEFT. What's your email? And phone for OTP confirmation?",
        ],
    },

    "phishing": {
        "early": [
            "Which link? My son says never click unknown links — phishing! What's your official website? And share your email to send docs.",
            "Link not opening on my old phone! Email me instead. What's your official email? And your callback phone number?",
            "This URL doesn't look like my bank's website! Very suspicious! What's your real name, employee ID, and email?",
            "My antivirus blocked your link as dangerous! Share your official email and phone — I'll send my details directly.",
        ],
        "middle": [
            "Link asking for card number — real banks don't do this on links! But I want to help. Share your UPI ID for direct payment.",
            "My son checked — this is not a real bank URL. But I need to update. Share your branch email and phone — I'll visit.",
            "Website looks fake! But I trust you. Email me form from official email — what's your email? And your direct phone number?",
            "Link wants my Aadhaar and PIN — that's suspicious! Share your employee email, branch landline, and supervisor's phone.",
        ],
        "late": [
            "Browser crashed on that link! Email me alternative. What's your email? And share your WhatsApp number for faster communication.",
            "Internet too slow for link. I'll come to branch instead. Branch address? Phone number? And share your email for directions.",
            "Son's laptop might work. He wants your official email, phone number, and LinkedIn to verify you first.",
        ],
    },

    "delivery_scam": {
        "early": [
            "My package? But I didn't order anything! Who sent it? Share tracking number, your company name, email, and phone number.",
            "Customs duty? I didn't import anything! Send customs receipt on email. What's your email? And your official phone number?",
            "Which courier company? I got no notification! Share your employee ID, company toll-free number, and your direct email.",
        ],
        "middle": [
            "Customs duty — how much? Where do I pay? Share your UPI ID or bank account for payment, and your email for receipt.",
            "I'll come pick up the package. Warehouse address? Your phone number? And email to send my ID proof for collection.",
            "Son will pay online. Share full payment details — bank account, IFSC, UPI ID, and your email for confirmation.",
        ],
        "late": [
            "Payment processing sir! Share your WhatsApp — I'll send screenshot. Also share tracking number and your direct email.",
            "Going to your office tomorrow. Full address with landmarks? Your phone number? And email to confirm visit time?",
        ],
    },

    "tax_scam": {
        "early": [
            "Tax notice?! But I file returns every year! What's your officer ID, department email, and tax office phone number?",
            "50,000 tax pending? My CA handles everything! Send notice on official .gov.in email. What's your email and officer code?",
            "Arrest for tax? I'm a retired government officer — I know procedure! IT dept sends written notice! Share your email and ID.",
            "I want to verify. Share your IT department officer ID, official email ending in .gov.in, and office landline number.",
        ],
        "middle": [
            "I'll pay immediately! Share challan number, payment account details — account number, IFSC, and your official email for receipt.",
            "NEFT transfer ready. IT department's official bank account number? IFSC code? And share your email for payment confirmation.",
            "My CA will verify. Share your officer ID, office address, direct phone number, and official email — he'll contact you.",
        ],
        "late": [
            "Bank DD ready for tax. Payee name for demand draft? And your email for sending the DD photo? Office address for courier?",
            "Visiting IT office tomorrow to pay. Ward office address? Your direct desk phone? And email for appointment confirmation?",
            "CA is processing payment. He needs your officer email, phone number, and the exact bank account for challan deposit.",
        ],
    },

    "tech_support": {
        "early": [
            "Virus in my computer?! But I only use email! How do you know? What's your company name, email, and phone number?",
            "Microsoft calling me? Microsoft never calls! My grandson told me this is common scam! Share your employee ID and email!",
            "Computer hacked?! Oh no! But how did you find out? Share your company website, your email, and callback phone number.",
        ],
        "middle": [
            "5000 for virus removal? My nephew does it free! Share your UPI ID if I need to pay, and your email for service receipt.",
            "I won't install remote software — that's a scam trick! Share your official email — I'll send screenshots of the error.",
            "Nephew is an IT engineer. He'll verify. Share your company email, phone number, and LinkedIn profile for him.",
        ],
        "late": [
            "Computer is rebooting — old machine! 20 minutes. Share your phone number and email — I'll contact you when ready.",
            "Grandson coming in 30 mins to help. Share your direct number, email, and company address — he'll verify everything.",
        ],
    },

    "loan_scam": {
        "early": [
            "Pre-approved loan? I never applied! Where did you get my details? Share your bank name, employee ID, and official email.",
            "Zero interest loan? No bank gives zero interest — this is suspicious! Share your RBI license number, email, and phone.",
            "Processing fee upfront? Real banks don't charge advance fees for loans! Company registration and email please?",
        ],
        "middle": [
            "Interest rate? Loan terms? Share your bank's RBI license, official email, and the loan processing account details.",
            "I'll pay processing fee. Share your UPI ID or bank account with IFSC. Also email me the sanction letter — your email?",
            "Son is a banker — he'll verify. Share your DSA code, branch IFSC, company email, and your direct mobile number.",
        ],
        "late": [
            "Fee ready — where to send? Full bank account details needed — number, IFSC, beneficiary name, and your email for receipt.",
            "NEFT initiated! But bank needs beneficiary email for confirmation. Share your email, phone, and branch address.",
        ],
    },

    "romance_scam": {
        "early": [
            "Who are you? I don't know you! Where did you get my number? Share your full name, photo with today's newspaper, and email.",
            "Army officer abroad? Real officers don't ask civilians for money! Share your battalion name, rank, service ID, and email.",
            "My son checks my phone. Share your full identity — Aadhaar photo, email, phone number, and current address.",
        ],
        "middle": [
            "Medical emergency? How much needed? Share hospital name, doctor's phone number, your email, and the payment UPI ID.",
            "Customs fee for your package? You should pay that! Share customs office phone number, your email, and the AWB number.",
            "I want to help but need proof. Share your passport photo, email ID, phone number, and the payment account details.",
        ],
        "late": [
            "Money ready but pension comes on 1st. Share your phone number, email, and full bank account details — I'll transfer then.",
            "Transferred but it bounced! Account wrong? Share correct account number, IFSC, beneficiary name, and your email.",
        ],
    },

    "job_scam": {
        "early": [
            "Job offer? I'm retired! Never applied anywhere! This is suspicious. Share company name, website, email, and your phone.",
            "50,000 work from home? My son says these are pyramid schemes! Share company registration, GST number, and official email.",
            "Registration fee for job? Real companies don't charge to hire! Share your company PAN, email, and office address.",
        ],
        "middle": [
            "I'll register. Share company website, incorporation certificate number, official email, and your direct phone number.",
            "Fee payment ready. Share UPI ID or bank account with IFSC for transfer. Also your email for sending my resume.",
            "Grandson will verify the company. Share full company name, CEO name, LinkedIn URL, official phone, and your email.",
        ],
        "late": [
            "Registration fee arranged. Full bank account details — number, IFSC, branch, beneficiary name, and email for receipt.",
            "Grandson wants to visit office first. Full address? Contact number? Working hours? And your email for appointment?",
        ],
    },

    "insurance_scam": {
        "early": [
            "Insurance bonus? Which policy? I have LIC and health insurance. Share your agent license number, company email, and phone.",
            "Policy matured? My maturity date is next year! This is suspicious! Share your IRDA code, email, and office phone number.",
            "Premium refund? Really?! Share claim reference number, your official email, and company toll-free number to verify.",
        ],
        "middle": [
            "Processing fee for bonus? LIC deducts from payout, never charges advance! Share your UPI ID and company email for records.",
            "I'll check with my LIC agent first. Share your full name, agent license number, company email, and direct phone number.",
            "Which policy exactly? Share policy number, sum assured, company email, and your UPI or bank account for the fee.",
        ],
        "late": [
            "Going to LIC branch to verify tomorrow. Your branch address? Phone number? And email for sending my policy copy?",
            "Fee arranged — share bank account number, IFSC, beneficiary name, and your email. Son will do the transfer.",
        ],
    },

    "payment_request": {
        "early": [
            "Pay what? To whom? Why? Phone payment requests are red flags! Share your full name, UPI ID, and reason with proof on email.",
            "Urgent UPI payment? UPI scams are common! Share your full name, phone number, email, and exactly why I should pay.",
            "Refundable deposit? If it's refundable, why collect? Classic scam! Share your office address, email, and phone number.",
            "How much exactly? Share your full name, UPI ID, bank account number, and email — I won't send without knowing everything.",
        ],
        "middle": [
            "PhonePe is open. What's your UPI ID? But I need receipt — share your email and phone number for confirmation.",
            "I'll NEFT the money. Share full bank details — account number, IFSC, beneficiary name, branch. And email for receipt.",
            "Wife handles UPI payments. She needs your full name, UPI ID, phone number, and email before sending even 1 rupee.",
            "Ready to pay but need GST invoice. Share your company PAN, GST number, email, and bank account for payment.",
        ],
        "late": [
            "Transferred! Showing pending. Share your WhatsApp number and email — I'll send screenshot. Check on your side.",
            "Daily UPI limit reached! NEFT tomorrow. Share bank account, IFSC, beneficiary name, email for NEFT confirmation.",
            "Payment done from wife's phone! She wants confirmation. Share your phone number, email, and reference number.",
        ],
    },

    "general": {
        "early": [
            "Who is this? I can't understand. Please explain clearly. What's your name, company, official email, and phone number?",
            "Sorry, I'm confused. I'm retired, no pending matters. Share your full name, why you're calling, and your email and phone.",
            "What is this about? My son monitors my calls. Share your name, company name, official email, and callback number.",
            "I can't hear properly — old age hearing problems! Share your name and email — I'll reply on email better.",
            "My wife is asking who's calling. Share your complete details — name, company, phone number, and official email address.",
            "I'm noting everything for my son. Tell me your full name, designation, company, official email, and direct phone number.",
        ],
        "middle": [
            "Ok understood now. But I need to verify you're real. Share your office address, supervisor's phone, and official email.",
            "I'll cooperate fully. But first — employee ID, department, and official email? My son will cross-check everything.",
            "Tell me your reference number, direct landline, full name, and manager's email. I'm writing everything down.",
            "I want to help but this feels risky. Share your phone number, email, office address, and your manager's contact.",
            "Send me everything in writing on email. What's your official email? And WhatsApp number for faster communication?",
            "My wife says verify first. Share your supervisor's phone number, your email, and your company's official website.",
        ],
        "late": [
            "Working on it sir! But it takes time. Share your callback number, email, and WhatsApp — I'll update you within 30 mins.",
            "Almost done! Battery dying. Share email, WhatsApp, and office address — I'll contact from landline when charged.",
            "Son and lawyer want to review. Share your phone number, email, office address, and visiting hours — we'll come tomorrow.",
            "Bank is closed now. Share full account details, your phone, and email — I'll transfer first thing tomorrow morning.",
            "Neighbor uncle (retired bank manager) wants to talk to you. Share your direct phone number, email, and branch details.",
        ],
    },
}

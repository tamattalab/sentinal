"""
English Response Dataset — Designed to extract maximum intel from scammers.
Every response asks for 2-3 specific details (email, UPI, bank account, phone, address, name).
The victim persona cooperates but keeps asking the scammer to share their details first.
Covers all 15 competition scenarios + general fallback.
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
            "Sir my daughter works in bank too. She says always verify. Please share your department name and official email ID?",
            "I went to branch last month for KYC! Who gave you my number? Share your officer code and official bank email address.",
        ],
        "middle": [
            "My Aadhaar is ready. But where do I send the copy? Give me your official email ID and I'll email the documents.",
            "Ok fine, I'll share PAN. But I want to pay verification fee. What's your UPI ID? And which bank account should I transfer to?",
            "Documents are in my almirah. Meanwhile share your full name, employee ID, branch IFSC code, and your email for records.",
            "I found my PAN card. Should I email it? Share your email address. Also what's your direct phone number for callback?",
            "My son says I should verify first. Share your LinkedIn profile, official email, and your manager's phone number.",
            "I'll update KYC today itself. Tell me — what's the processing fee? Share your UPI ID or bank account number for payment.",
            "Which documents exactly? I have Aadhaar, PAN, passport all. Email me the list — your official email? And phone for callback?",
            "My neighbour also got similar call yesterday. Is this mass update? Share your zone office number and official email please.",
        ],
        "late": [
            "Documents ready sir! But my phone can't send photos. Share your email — I'll email everything. What's your WhatsApp number too?",
            "Wife found the papers! Where do I send? Give your email ID, WhatsApp number, and bank account for the fee payment.",
            "Almost done! Scanning documents now. Share your personal email and phone number — I'll send via WhatsApp and email both.",
            "Son is helping me scan. He wants your official email, phone number, and your manager's email for his records.",
            "Documents scanned! But file is 10MB, my email won't send. Share your WhatsApp number and I'll send there. Also your phone?",
            "Printer jammed while printing! Using neighbour's. Give me 10 minutes. Share your callback number and email for sending.",
        ],
    },

    "account_threat": {
        "early": [
            "BLOCKED?! Please don't! My pension is in that account! What's your name, employee ID, and complaint reference number?",
            "Account suspended?! But I paid all dues! This sounds like a scam — give me your full name, branch phone number, and email!",
            "Oh God! My daughter's wedding savings! Please help! What's your direct callback number and official email?",
            "Sir please don't block! Who do I talk to? Give me your supervisor's name, their phone number, and your employee email.",
            "My son says real banks send SMS, not calls. Share your branch address, landline number, and official email for verification.",
            "All my savings are there sir! Pension money! Please, what is your full name and employee code? Give me email to write complaint.",
            "Account blocked? But I just used ATM yesterday! Something wrong. Share your department email and officer badge number.",
            "Sir I'm old man, don't scare me like this! Tell me your name, designation, and official email — I'll verify from branch.",
        ],
        "middle": [
            "I'll pay the fine immediately! What's the amount? Share your UPI ID or bank account number with IFSC for NEFT transfer.",
            "Ready to resolve this sir. Need your reference number, your bank account details for payment, and your official email for receipt.",
            "My son is a banker — he'll verify. Give me your employee code, branch IFSC, the fine account number, and your email.",
            "I trust you sir. I'll pay now. PhonePe or Google Pay? Share your UPI ID. Also your phone number for payment confirmation.",
            "Ok sending payment. But I need written receipt. Share your bank account number, IFSC code, and your email for the receipt.",
            "Which amount exactly? 500 or 5000? Share UPI ID for small amount first as test. And your email for official receipt.",
            "I'll go to ATM if needed. Which branch? Share branch address, account number for deposit, and your email for confirmation.",
        ],
        "late": [
            "Payment initiated sir! Amount is showing pending. Share your phone number — I'll send screenshot on WhatsApp.",
            "Son went to ATM for cash. He wants your bank account number, IFSC, and branch address to deposit directly.",
            "Transfer done from my side! But error showing. Retry karna padega. Share your UPI ID again and your WhatsApp number.",
            "Almost paid! UPI is asking for receiver's name. What's the full name on the account? And your email for confirmation?",
            "Payment stuck — daily limit hit. Share your bank account for NEFT tomorrow morning. And your phone and email for updates.",
            "Bank showing server error jifor UPI! I'll try NEFT. Share account number, IFSC, beneficiary name, and your email.",
        ],
    },

    "otp_fraud": {
        "early": [
            "OTP?! My bank clearly says NEVER share OTP! This is the biggest red flag! Who are you? Share your employee ID and email!",
            "Sir, RBI says no one should ask for OTP! What's your full name, employee ID, and official bank email? I want to report this!",
            "My son warned me about OTP scams! I'll share if you prove identity — send me email from official bank domain. What's your email?",
            "OTP request? This is suspicious! Give me your supervisor's phone number, your name, and official email first!",
            "Wait wait, OTP means one-time password right? My grandson says never share this! What's your callback number and email?",
            "OTP kya hota hai sir? I don't understand these things. But my son says never tell anyone. Share your name and official email?",
            "RBI circular says OTP sharing is fraud! I read in newspaper! Share your officer ID, email, and branch landline number.",
            "I got scared hearing OTP! My neighbor lost 2 lakhs like this. Share your badge number and official email for verification.",
        ],
        "middle": [
            "OTP came but... my son is checking. Send verification from your official email first. What's your email ID and phone number?",
            "Reading OTP... 4... wait, need glasses. Meanwhile — what's your full name, employee badge number, and official email?",
            "Got 2 OTPs — which one? But first, email me authorization letter. Your email? And your direct phone number?",
            "I'll share OTP if you send written request. What's your official email ID? Also share your UPI ID for the processing fee.",
            "OTP is on screen. But I read wrong numbers last time. Share your WhatsApp — I'll send screenshot. What's your number?",
            "Which OTP — from SBI or HDFC? I have both accounts. Meanwhile share your email ID and phone number for record.",
            "My reading glasses broke sir! Can't see small numbers. Share your email — I'll forward the OTP message. What's your email?",
        ],
        "late": [
            "OTP expired sir! Send new one. My phone is slow. Meanwhile share your callback number and email — I'll respond from there.",
            "Phone died while reading OTP! Charging now. Share your email and WhatsApp number — I'll send it there when phone is on.",
            "Font too small, can't read! I'll email you screenshot. What's your email? And give phone number for callback.",
            "New OTP came but delivery boy is at door. 5 minutes! Share your WhatsApp number and email — I'll send both ways.",
            "OTP keeps expiring before I can read it! My eyes are weak. Share your email and I'll forward the SMS directly.",
            "Power cut! Phone battery at 5%. Share your email and WhatsApp number urgently — I'll send OTP from wife's phone.",
        ],
    },

    "lottery_scam": {
        "early": [
            "I WON?! But I never bought a ticket! How is this possible? Share your company registration, official email, and your phone number.",
            "50 Lakhs?! Really?! My wife won't believe this! What's your company name, website, email, and official phone number?",
            "Prize without ticket? My son says this is classic scam. Share your SEBI registration, company PAN, and official email.",
            "Amazing news! But I need to verify. Send certificate on your official email. What's the email? And your direct phone?",
            "Is this real? I never win anything! Please share your company name, your full name, email, and official phone number.",
            "My wife is crying with joy! But my son says verify first. Share your company website, email, and your phone number.",
        ],
        "middle": [
            "I'll pay the tax! How much exactly? Share your UPI ID or bank account number with IFSC. Also email me the winner certificate.",
            "I want to claim! Send me official letter on email. What's your email ID? And the bank account for tax payment with full details?",
            "My wife wants proof. Email the winner certificate — what's your email? Also share your phone number and office address.",
            "Tax payment ready. Share exact account — account number, IFSC code, bank name, branch address, and your official email.",
            "Will gold trophy come by courier? Share courier tracking details, your email, and the tax payment bank account info.",
            "I told all my neighbours about the prize! They want to see certificate. Email it to me — what's your email address?",
        ],
        "late": [
            "FD maturing next week for tax payment. Share your callback phone number, email, and bank account — I'll transfer immediately.",
            "Money ready sir! Where to send? Full bank account details — number, IFSC, beneficiary name. And your email for receipt.",
            "Wife wants to come to your office to pay personally. What's your full office address, landmarks, phone, and email?",
            "Selling gold chain for tax! Jeweller is weighing now. Share your full bank details and email — money coming within 1 hour!",
            "Village panchayat wants to felicitate me for winning! Share your company address and email — they'll send invitation.",
        ],
    },

    "investment_scam": {
        "early": [
            "200% guaranteed returns? My son says guaranteed returns is biggest scam sign! What's your SEBI registration and company email?",
            "Crypto investment? I don't understand crypto but I'm interested. Share your company website, your email, and phone number.",
            "Triple returns in 30 days? Share your company PAN, SEBI license, official email, and your direct mobile number.",
            "Interesting! But I need to verify. Share your company registration certificate on email. What's your email and phone?",
            "My retired friends lost money in similar schemes. But I'll listen. Share your AMFI registration, email, and phone?",
            "Bitcoin? Dogecoin? I read about these! Very risky! Share your trading license, official email, and company phone number.",
        ],
        "middle": [
            "I want to invest 5 lakhs! Where to send money? Share your company bank account number, IFSC, and your email for agreement.",
            "Send me investment agreement on email. What's your email? Also share UPI ID for first installment and your phone for support.",
            "My son wants to invest too! Send details — your full name, company email, bank account number, and IFSC code.",
            "How do I start? Share payment details — UPI ID and bank account. Also your official email and WhatsApp for communication.",
            "Minimum investment 10000? Ok I'll start small. Share your UPI ID for transfer and email for investment certificate.",
            "My wife also wants to invest her savings! Maximum limit? Share all details — bank account, UPI, email, phone.",
        ],
        "late": [
            "Selling my FD to invest with you! Share full bank details — account number, IFSC, beneficiary name, email for confirmation.",
            "Wife also wants to invest! Maximum limit? Share all payment channels — UPI, bank account, IFSC, and email for receipts.",
            "Transfer initiated! But bank needs beneficiary email for NEFT. What's your email? And phone for OTP confirmation?",
            "Breaking FD today! Gold rates are good too — selling jewellery. Share bank account and email for sending everything.",
        ],
    },

    "phishing": {
        "early": [
            "Which link? My son says never click unknown links — phishing! What's your official website? And share your email to send docs.",
            "Link not opening on my old phone! Email me instead. What's your official email? And your callback phone number?",
            "This URL doesn't look like my bank's website! Very suspicious! What's your real name, employee ID, and email?",
            "My antivirus blocked your link as dangerous! Share your official email and phone — I'll send my details directly.",
            "My grandson installed antivirus — it's blocking your link! Share your official bank email and I'll respond there.",
            "Link is showing red warning on Chrome! Share your official email — I'll send details that way instead. What's your email?",
        ],
        "middle": [
            "Link asking for card number — real banks don't do this on links! But I want to help. Share your UPI ID for direct payment.",
            "My son checked — this is not a real bank URL. But I need to update. Share your branch email and phone — I'll visit.",
            "Website looks fake! But I trust you. Email me form from official email — what's your email? And your direct phone number?",
            "Link wants my Aadhaar and PIN — that's suspicious! Share your employee email, branch landline, and supervisor's phone.",
            "Link loads but then crashes! Old phone problem. Share your email and I'll send documents directly. What's your phone too?",
        ],
        "late": [
            "Browser crashed on that link! Email me alternative. What's your email? And share your WhatsApp number for faster communication.",
            "Internet too slow for link. I'll come to branch instead. Branch address? Phone number? And share your email for directions.",
            "Son's laptop might work. He wants your official email, phone number, and LinkedIn to verify you first.",
            "Internet data finished! Recharging now. Share your email, phone, and WhatsApp — I'll send from WiFi at home.",
        ],
    },

    "delivery_scam": {
        "early": [
            "My package? But I didn't order anything! Who sent it? Share tracking number, your company name, email, and phone number.",
            "Customs duty? I didn't import anything! Send customs receipt on email. What's your email? And your official phone number?",
            "Which courier company? I got no notification! Share your employee ID, company toll-free number, and your direct email.",
            "Package from foreign? Nobody sends me anything! Share sender's name, tracking number, your email, and office phone.",
        ],
        "middle": [
            "Customs duty — how much? Where do I pay? Share your UPI ID or bank account for payment, and your email for receipt.",
            "I'll come pick up the package. Warehouse address? Your phone number? And email to send my ID proof for collection.",
            "Son will pay online. Share full payment details — bank account, IFSC, UPI ID, and your email for confirmation.",
            "How much is customs duty exactly? Share the fee amount, your UPI ID, bank account details, and email for official receipt.",
        ],
        "late": [
            "Payment processing sir! Share your WhatsApp — I'll send screenshot. Also share tracking number and your direct email.",
            "Going to your office tomorrow. Full address with landmarks? Your phone number? And email to confirm visit time?",
            "Payment done! But courier saying different amount. Check from your side. Share your phone, email, and tracking number.",
        ],
    },

    "tax_scam": {
        "early": [
            "Tax notice?! But I file returns every year! What's your officer ID, department email, and tax office phone number?",
            "50,000 tax pending? My CA handles everything! Send notice on official .gov.in email. What's your email and officer code?",
            "Arrest for tax? I'm a retired government officer — I know procedure! IT dept sends written notice! Share your email and ID.",
            "I want to verify. Share your IT department officer ID, official email ending in .gov.in, and office landline number.",
            "Income tax calls on mobile? IT department uses official channel! Share your PAN verification portal, email, and officer ID.",
            "My CA filed on time! Zero pending! Share your IT department email and case reference number — my CA will respond.",
        ],
        "middle": [
            "I'll pay immediately! Share challan number, payment account details — account number, IFSC, and your official email for receipt.",
            "NEFT transfer ready. IT department's official bank account number? IFSC code? And share your email for payment confirmation.",
            "My CA will verify. Share your officer ID, office address, direct phone number, and official email — he'll contact you.",
            "Which assessment year? Share exact details — AY number, challan code, payment bank account, and your email for correspondence.",
        ],
        "late": [
            "Bank DD ready for tax. Payee name for demand draft? And your email for sending the DD photo? Office address for courier?",
            "Visiting IT office tomorrow to pay. Ward office address? Your direct desk phone? And email for appointment confirmation?",
            "CA is processing payment. He needs your officer email, phone number, and the exact bank account for challan deposit.",
            "Payment processing sir! CA is doing NEFT. Share exact bank account, IFSC, and your email for confirmation receipt.",
        ],
    },

    "tech_support": {
        "early": [
            "Virus in my computer?! But I only use email! How do you know? What's your company name, email, and phone number?",
            "Microsoft calling me? Microsoft never calls! My grandson told me this is common scam! Share your employee ID and email!",
            "Computer hacked?! Oh no! But how did you find out? Share your company website, your email, and callback phone number.",
            "My grandson is IT engineer — he says Microsoft never calls! Share your employee ID, company email, and phone to verify.",
        ],
        "middle": [
            "5000 for virus removal? My nephew does it free! Share your UPI ID if I need to pay, and your email for service receipt.",
            "I won't install remote software — that's a scam trick! Share your official email — I'll send screenshots of the error.",
            "Nephew is an IT engineer. He'll verify. Share your company email, phone number, and LinkedIn profile for him.",
            "Which antivirus? My grandson uses Kaspersky. Share your company email and I'll forward the error logs. Phone number too?",
        ],
        "late": [
            "Computer is rebooting — old machine! 20 minutes. Share your phone number and email — I'll contact you when ready.",
            "Grandson coming in 30 mins to help. Share your direct number, email, and company address — he'll verify everything.",
            "Windows update started! 45 mins estimated. Share your callback phone, email, and WhatsApp — I'll send when done.",
        ],
    },

    "loan_scam": {
        "early": [
            "Pre-approved loan? I never applied! Where did you get my details? Share your bank name, employee ID, and official email.",
            "Zero interest loan? No bank gives zero interest — this is suspicious! Share your RBI license number, email, and phone.",
            "Processing fee upfront? Real banks don't charge advance fees for loans! Company registration and email please?",
            "1 crore loan pre-approved? At my age? This is suspicious! Share your bank DSA code, official email, and phone.",
        ],
        "middle": [
            "Interest rate? Loan terms? Share your bank's RBI license, official email, and the loan processing account details.",
            "I'll pay processing fee. Share your UPI ID or bank account with IFSC. Also email me the sanction letter — your email?",
            "Son is a banker — he'll verify. Share your DSA code, branch IFSC, company email, and your direct mobile number.",
            "Processing fee is how much? Share exact amount, UPI ID for payment, bank account details, and email for loan agreement.",
        ],
        "late": [
            "Fee ready — where to send? Full bank account details needed — number, IFSC, beneficiary name, and your email for receipt.",
            "NEFT initiated! But bank needs beneficiary email for confirmation. Share your email, phone, and branch address.",
            "Fee arranged sir! Son is doing UPI payment. Share UPI ID, your callback phone, and email for sanction letter.",
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
            "My grandson is in HR — he says job scams are common! Share your company's CIN number, website, and official email.",
        ],
        "middle": [
            "I'll register. Share company website, incorporation certificate number, official email, and your direct phone number.",
            "Fee payment ready. Share UPI ID or bank account with IFSC for transfer. Also your email for sending my resume.",
            "Grandson will verify the company. Share full company name, CEO name, LinkedIn URL, official phone, and your email.",
            "My grandson wants to apply too! Share job posting link, company email, HR phone number, and registration details.",
        ],
        "late": [
            "Registration fee arranged. Full bank account details — number, IFSC, branch, beneficiary name, and email for receipt.",
            "Grandson wants to visit office first. Full address? Contact number? Working hours? And your email for appointment?",
            "Payment processing! UPI limit reached on this phone. Share bank account for NEFT, your email and WhatsApp for confirmation.",
        ],
    },

    "insurance_scam": {
        "early": [
            "Insurance bonus? Which policy? I have LIC and health insurance. Share your agent license number, company email, and phone.",
            "Policy matured? My maturity date is next year! This is suspicious! Share your IRDA code, email, and office phone number.",
            "Premium refund? Really?! Share claim reference number, your official email, and company toll-free number to verify.",
            "Which insurance — LIC, health, or vehicle? Share your IRDA registration, agent code, company email, and phone.",
        ],
        "middle": [
            "Processing fee for bonus? LIC deducts from payout, never charges advance! Share your UPI ID and company email for records.",
            "I'll check with my LIC agent first. Share your full name, agent license number, company email, and direct phone number.",
            "Which policy exactly? Share policy number, sum assured, company email, and your UPI or bank account for the fee.",
            "Bonus amount is how much? Share exact figure, your IRDA code, email for documents, and bank account for fee payment.",
        ],
        "late": [
            "Going to LIC branch to verify tomorrow. Your branch address? Phone number? And email for sending my policy copy?",
            "Fee arranged — share bank account number, IFSC, beneficiary name, and your email. Son will do the transfer.",
            "LIC agent says he'll verify. Share your direct phone, email, and office address — he'll call you tomorrow.",
        ],
    },

    # === NEW CATEGORIES for missing competition scenarios ===

    "electricity_scam": {
        "early": [
            "Electricity cut?! But I paid last month! I have the receipt! Share your employee ID, sub-division office phone, and email!",
            "Bill unpaid? I use auto-pay! Show me on official portal! Share your DISCOM official email and employee badge number.",
            "Power disconnection notice? My metre reader didn't mention anything! Share your officer name, email, and office landline.",
            "I paid via PhonePe last week! Share your billing department email, your employee ID, and official helpline number.",
            "Sir I have heart patient at home — can't cut power! Share your complaint number, official email, and supervisor's phone.",
        ],
        "middle": [
            "How much exactly? I'll pay right now. Share your official UPI ID or bank account. And email me the pending bill copy.",
            "OK sending payment. Which mode — UPI or NEFT? Share your DISCOM bank account, IFSC, and email for receipt.",
            "My son will pay online. Share the official payment portal link, CA number, and your email and phone for confirmation.",
            "Payment ready but I want receipt. Share your UPI ID for payment, official email for e-receipt, and helpline number.",
        ],
        "late": [
            "Bill pay ho gaya sir! But confirmation not coming. Share your WhatsApp and email — I'll send screenshot.",
            "ATM down in my area! Will pay tomorrow first thing. Share your callback number, email, and UPI ID for direct pay.",
            "Son is transferring now. Share bank account details, IFSC, your phone number, and email for payment confirmation.",
        ],
    },

    "customs_scam": {
        "early": [
            "Customs seized my parcel?! But I didn't order anything from abroad! Share seizure notice, your badge ID, email, and phone.",
            "Drugs in my parcel?! That's impossible! I want to see the FIR! Share your officer ID, official email, and station phone.",
            "NDPS Act?! Sir I'm a retired teacher! Share your customs division, badge number, official email, and station landline.",
            "Which courier was it? I track all my parcels! Share AWB number, your officer email, and customs helpline number.",
        ],
        "middle": [
            "Fine amount? How to pay? Share your official bank account, IFSC code, and customs email for sending payment proof.",
            "I'll pay to avoid trouble. Share the exact fine, payment UPI ID or bank account, and your official email for receipt.",
            "My lawyer says I need written notice. Share your email, customs station address, phone, and case file number.",
            "Paying now sir! Share customs bank account number, IFSC, and your official email. Also tell me clearance timeline.",
        ],
        "late": [
            "Lawyer is arranging payment. Share complete bank details, your officer email, and case reference number.",
            "Transfer initiated by my son. Share your phone for confirmation, email for receipt, and customs clearance form.",
            "Payment ready sir. Exact bank account? IFSC? Beneficiary? And your email and phone for post-payment clearance?",
        ],
    },

    "govt_scam": {
        "early": [
            "Govt scheme? Which ministry? I'm careful with my pension! Share your official .gov.in email, officer ID, and helpline.",
            "PM scheme approved? But I never applied! How did I get selected? Share official notification, your email, and phone.",
            "Housing scheme allotment? Really? Share your ministry name, official .gov.in email, and officer designation with phone.",
            "Subsidy sanction? My ration card is linked to Aadhaar! Share your department, official email, helpline, and officer ID.",
        ],
        "middle": [
            "Processing fee for scheme? Govt schemes don't charge! But I'll pay if real. Share UPI ID, bank account, and official email.",
            "I need written letter on letterhead. Share your official email, department postal address, and phone for verification.",
            "My MLA's office will verify. Share your officer name, department email, phone, and the scheme notification number.",
            "Ready to pay registration. Share exact amount, payment bank account, IFSC, and your official email for acknowledgement.",
        ],
        "late": [
            "Fee arranged by son. Share full bank account details, IFSC, beneficiary name, your email and phone for receipt.",
            "Going to collector office tomorrow to verify. Share your department, officer name, email, and phone for appointment.",
            "Payment processing! Share bank account, IFSC, your phone and email — son is doing NEFT transfer right now.",
        ],
    },

    "refund_scam": {
        "early": [
            "Refund of 1500? From where? I don't remember any pending refund! Share your company name, order number, email, and phone.",
            "Bank refund failed? I didn't get any refund notification! Share your employee ID, official email, and bank helpline number.",
            "Which transaction refund? Give me the original order number, your name, official email, and customer care phone number.",
            "Refund from which company? Amazon? Flipkart? Share order ID, your official email, and company customer support number.",
        ],
        "middle": [
            "Bank details for refund? Share your company verification email first. And give me your phone number for callback.",
            "I'll share IFSC but which bank needs it? Share your official email, the refund reference number, and your phone.",
            "Wife handles bank — she wants your official email, company customer care number, and refund authorization letter.",
            "Refund amount and order details please. Also share your official email and phone — my son will verify on his end.",
        ],
        "late": [
            "Shared details but no refund yet! Check from your end. Share your email, phone, and escalation manager's number.",
            "Son checking bank statement — no credit. Share your official email, complaint number, and supervisor's phone for follow-up.",
            "Still waiting for refund! Share your UPI reference, company email, customer care number, and estimated timeline.",
        ],
    },

    "payment_request": {
        "early": [
            "Pay what? To whom? Why? Phone payment requests are red flags! Share your full name, UPI ID, and reason with proof on email.",
            "Urgent UPI payment? UPI scams are common! Share your full name, phone number, email, and exactly why I should pay.",
            "Refundable deposit? If it's refundable, why collect? Classic scam! Share your office address, email, and phone number.",
            "How much exactly? Share your full name, UPI ID, bank account number, and email — I won't send without knowing everything.",
            "Random payment request? This is suspicious! Share your identity proof, official email, company phone, and reason.",
        ],
        "middle": [
            "PhonePe is open. What's your UPI ID? But I need receipt — share your email and phone number for confirmation.",
            "I'll NEFT the money. Share full bank details — account number, IFSC, beneficiary name, branch. And email for receipt.",
            "Wife handles UPI payments. She needs your full name, UPI ID, phone number, and email before sending even 1 rupee.",
            "Ready to pay but need GST invoice. Share your company PAN, GST number, email, and bank account for payment.",
            "Payment mode? I have GPay and PhonePe both. Share your UPI ID for direct transfer and email for receipt.",
        ],
        "late": [
            "Transferred! Showing pending. Share your WhatsApp number and email — I'll send screenshot. Check on your side.",
            "Daily UPI limit reached! NEFT tomorrow. Share bank account, IFSC, beneficiary name, email for NEFT confirmation.",
            "Payment done from wife's phone! She wants confirmation. Share your phone number, email, and reference number.",
            "UPI failed — wrong VPA maybe? Re-share your UPI ID, bank account for NEFT backup, and your email.",
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
            "You called me or I called you? I'm confused! Share your name, department, email, and phone — I'll check with son.",
            "Is this a prank call? My grandson does this sometimes! Tell me your real name, company, email, and phone number.",
        ],
        "middle": [
            "Ok understood now. But I need to verify you're real. Share your office address, supervisor's phone, and official email.",
            "I'll cooperate fully. But first — employee ID, department, and official email? My son will cross-check everything.",
            "Tell me your reference number, direct landline, full name, and manager's email. I'm writing everything down.",
            "I want to help but this feels risky. Share your phone number, email, office address, and your manager's contact.",
            "Send me everything in writing on email. What's your official email? And WhatsApp number for faster communication?",
            "My wife says verify first. Share your supervisor's phone number, your email, and your company's official website.",
            "I'm sitting in temple right now. Share your email and phone — I'll call back in 30 minutes sharp.",
            "My spectacles broke! Can't read anything. Share your email — I'll have my grandson respond. What's your phone too?",
        ],
        "late": [
            "Working on it sir! But it takes time. Share your callback number, email, and WhatsApp — I'll update you within 30 mins.",
            "Almost done! Battery dying. Share email, WhatsApp, and office address — I'll contact from landline when charged.",
            "Son and lawyer want to review. Share your phone number, email, office address, and visiting hours — we'll come tomorrow.",
            "Bank is closed now. Share full account details, your phone, and email — I'll transfer first thing tomorrow morning.",
            "Neighbor uncle (retired bank manager) wants to talk to you. Share your direct phone number, email, and branch details.",
            "Pooja going on at home — can't talk now! Share your email, phone, and WhatsApp — I'll respond after 1 hour.",
        ],
    },
}

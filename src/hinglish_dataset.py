"""
Hinglish Response Dataset — Hindi-English mix, maximum intel extraction.
Every response asks for scammer's email, UPI, bank account, phone, address, or name.
"""

HINGLISH_DB = {

    "kyc_fraud": {
        "early": [
            "KYC update? Par meine toh pichle saal karwaya tha! Aapka employee ID aur official email kya hai? Pehle verify karunga!",
            "Arrey bhai, bank phone pe KYC nahi maangta! Aapka full name, branch address, aur email bhejo verify karne ke liye!",
            "KYC expire? Mujhe toh koi SMS nahi aaya! Aapka naam, employee ID, aur official email dijiye — main check karunga!",
            "Haan ji KYC karunga. Par pehle aapka supervisor ka number aur official email do — phone pe maangna red flag hai!",
            "Beta bol raha hai pehle verify karo. Aapka email ID kya hai? Employee badge number? Aur branch ka landline?",
        ],
        "middle": [
            "Aadhaar card ready hai. Kahan bhejoon? Aapka official email do — wahi bhej dunga. Aur UPI ID do fee ke liye.",
            "PAN card mil gaya. Email pe bhejta hoon. Aapka email address kya hai? Aur phone number bhi do callback ke liye.",
            "Theek hai cooperate karunga. Par pehle — aapka full name, employee ID, branch IFSC code, aur email dijiye!",
            "Documents scan kar raha hoon. Aapka email do bhejne ke liye. Aur bank account number bhi do processing fee ke liye.",
            "Beta verify karega pehle. Aapka LinkedIn profile, official email, phone number, aur manager ka contact dijiye.",
        ],
        "late": [
            "Papers mil gaye! Phone se photo nahi ja rahi. Aapka email do — laptop se bhejta hoon. WhatsApp number bhi do!",
            "Sab ready hai sir! Kahan bhejoon? Email ID, WhatsApp number, aur fee ke liye bank account number dijiye!",
            "Beta scan kar raha hai. Usse chahiye — aapka official email, phone number, aur manager ka email bhi!",
        ],
    },

    "account_threat": {
        "early": [
            "BLOCK?! Hai Ram! Meri beti ki shaadi ka paisa hai! Aapka naam, employee ID, aur official email kya hai?!",
            "Account suspend?! Par maine sab dues clear kiye! Aapka branch ka phone number, email, aur complaint number batao!",
            "Sir please block mat karo! Kyun ho raha hai? Aapka full name, supervisor ka number, aur official email dijiye!",
            "Arrey baap re! Pension ka paisa hai! Phone pe threatening toh scam hai! Aapka email aur employee ID do pehle!",
        ],
        "middle": [
            "Fine kitna hai? Main abhi pay karta hoon! Aapka UPI ID ya bank account number with IFSC batao. Email bhi do receipt ke liye!",
            "Pay kar dunga sir. Par reference number, bank account details, IFSC, aur email chahiye payment proof ke liye!",
            "Beta banker hai woh verify karega. Branch IFSC, account number jisme pay karna hai, aur aapka email dijiye!",
            "PhonePe se bhej raha hoon. UPI ID kya hai aapka? Aur phone number do confirmation ke liye. Email bhi do!",
        ],
        "late": [
            "Paisa bhej diya sir! Par pending dikha raha hai. WhatsApp number do screenshot bhejta hoon. Email bhi do!",
            "Beta ATM gaya hai. Usse chahiye — bank account number, IFSC, branch address, aur aapka email. Phone number bhi do!",
            "Transfer ho gaya! Error aa raha hai. Aapka UPI ID phir se do. WhatsApp number aur email bhi do pls!",
        ],
    },

    "otp_fraud": {
        "early": [
            "OTP?! Bank hamesha bolta hai OTP kabhi share mat karo! Sabse bada red flag! Aapka employee ID aur email kya hai?!",
            "Sir RBI ne bhi warning di hai OTP mat do! Aapka naam, employee ID, aur official email batao pehle verify ke liye!",
            "OTP maangna = fraud! TV pe dekha hai! Aapka supervisor ka phone number, aapki email, aur branch address do!",
            "Beta bol raha hai OTP mat dena! Pehle aapka email bhejo proof ke saath. Callback number bhi do!",
        ],
        "middle": [
            "OTP aa gaya hai par... beta bol raha hai pehle verify karo. Aapka email kya hai? Phone number bhi do callback ke liye!",
            "OTP padh raha hoon... 4... glasses chahiye. Tab tak aapka full name, employee ID, aur email note kar leta hoon!",
            "Do OTP aaye hain — kaunsa wala? Pehle email pe authorization bhejo. Aapka email aur UPI ID kya hai?",
            "OTP dunga par pehle written request email karo. Aapka email ID, phone number, aur UPI ID bhi chahiye fee ke liye!",
        ],
        "late": [
            "OTP expire ho gaya! Naya bhejo. Tab tak aapka phone number aur email do — screenshot bhejta hoon naye OTP ka!",
            "Phone charge ho raha hai doosre room mein! 5 min ruko. Email aur WhatsApp number do wapas bhejne ke liye!",
            "Galat OTP pad diya — grocery delivery ka tha! Sahi wala pending. Aapka email do — screenshot bhejta hoon!",
        ],
    },

    "lottery_scam": {
        "early": [
            "JEETA?! Sach mein?! Par ticket toh nahi kharida! Aapka company name, email, phone number, aur registration kya hai?",
            "50 Lakh?! Bina ticket ke lottery kaise — suspicious hai! Company ka website, official email, aur phone number batao!",
            "Prize?! Beta bolta hai lottery scam hote hain! Company GST, SEBI registration, aur official email do pehle!",
        ],
        "middle": [
            "Tax pay karunga! Kitna hai? UPI ID ya bank account number IFSC ke saath batao. Email pe winner certificate bhejo!",
            "Claim karna chahta hoon! Official lottery letter email pe bhejo. Email ID kya hai? Bank account bhi batao tax ke liye!",
            "Wife proof chahti hai. Winner certificate email karo — email kya hai? Aur phone number aur office address bhi do!",
        ],
        "late": [
            "FD next week mature hoga tax ke liye. Bank account details — number, IFSC, beneficiary name do. Aur email bhi!",
            "Paisa ready hai! Kahan bhejoon? Full bank details, email, aur phone number do — transfer karunga abhi!",
        ],
    },

    "investment_scam": {
        "early": [
            "200% returns guaranteed?! Beta bolta hai guaranteed returns = scam! SEBI registration, company email aur phone do!",
            "Crypto mein invest? Samajh nahi aata par interest hai. Company website, email, aur aapka phone number batao!",
            "Triple returns 30 din mein? Ponzi scheme jaisa lag raha hai! Company PAN, SEBI license, aur email dijiye!",
        ],
        "middle": [
            "5 Lakh invest karunga! Paisa kahan bhejoon? Bank account number, IFSC, aur email do agreement bhejne ke liye!",
            "Investment agreement email pe bhejo. Email kya hai? UPI ID bhi do first installment ke liye. Phone number bhi!",
            "Beta bhi invest karega! Full details do — naam, company email, bank account, IFSC code sab!",
        ],
        "late": [
            "FD tod raha hoon invest ke liye! Bank account, IFSC, beneficiary name, aur email do — transfer karunga!",
            "Wife bhi invest karegi! Maximum limit? UPI, account, IFSC, email — sab do. Dono ka invest karunga!",
        ],
    },

    "phishing": {
        "early": [
            "Kaun sa link? Beta bolta hai unknown links = phishing! Aapka official website kya hai? Email pe bhejo documents!",
            "Link nahi khul raha old phone pe! Email pe bhejo! Aapka official email kya hai? Phone number bhi do!",
            "Yeh URL toh fake dikh raha hai! Red flag hai! Aapka asal naam, employee ID, aur email batao!",
        ],
        "middle": [
            "Link card number maang raha hai — banks aisa nahi karte! UPI se pay kar deta hoon. UPI ID aur email kya hai?",
            "Beta ne check kiya — fake domain hai! Par help chahiye. Branch email, phone number, aur address do!",
            "Website Aadhaar aur PIN maang rahi hai — suspicious! Employee email, branch landline, aur supervisor ka phone do!",
        ],
        "late": [
            "Browser crash ho gaya! Email pe alternative bhejo. Aapka email kya hai? WhatsApp number bhi do!",
            "Internet slow hai. Branch mein aake dunga. Full address, phone number, aur email do directions ke liye!",
        ],
    },

    "delivery_scam": {
        "early": [
            "Mera package? Par order toh nahi kiya! Kisne bheja? Tracking number, company email, aur phone number do!",
            "Customs duty? Import nahi kiya! Customs receipt email pe bhejo. Email kya hai? Phone number bhi do!",
            "Kaun si courier company? Notification nahi aaya! Employee ID, toll-free number, aur email dijiye!",
        ],
        "middle": [
            "Duty kitna hai? Kahan pay karoon? UPI ID ya bank account batao. Email bhi do receipt ke liye!",
            "Son pay karega. Full payment details — bank account, IFSC, UPI ID, aur email do confirmation ke liye!",
        ],
        "late": [
            "Payment ho raha hai sir! WhatsApp do screenshot bhejta hoon. Email aur tracking number bhi do!",
            "Office aake dunga kal. Full address kya hai? Phone, email, aur visiting hours bhi batao!",
        ],
    },

    "tax_scam": {
        "early": [
            "Tax notice?! Har saal return file karta hoon! Officer ID, department email, aur office phone number batao!",
            "50,000 tax baki? CA sab handle karta hai! .gov.in email se notice bhejo. Email aur officer code kya hai?",
            "Arrest karenge? Main 30 saal government mein tha — IT dept phone pe nahi maangta! Email aur officer ID do!",
        ],
        "middle": [
            "Abhi pay karta hoon! Challan number, bank account number, IFSC, aur official email do receipt ke liye!",
            "NEFT karunga. IT dept ka account number aur IFSC do. Email bhi do payment confirmation bhejne ke liye!",
            "CA se baat karunga. Aapka officer ID, office address, phone number, aur email — sab do CA ke liye!",
        ],
        "late": [
            "Bank DD bana raha hai. Payee name, office address, aur email do demand draft courier karne ke liye!",
            "CA payment process kar raha hai. Officer email, phone, aur exact bank account for challan deposit do!",
        ],
    },

    "tech_support": {
        "early": [
            "Computer mein virus?! Sirf email ke liye use karta hoon! Company name, email, aur phone number kya hai?",
            "Microsoft call nahi karta — pota bola tha! Yeh scam hai! Employee ID, email, aur company website do!",
            "Hack ho gaya?! Aapko kaise pata? Bahut suspicious hai! Company website, email, aur manager ka phone do!",
        ],
        "middle": [
            "5000 virus removal ke liye? UPI ID kya hai pay karne ke liye? Email bhi do service receipt ke liye!",
            "Remote software nahi install karunga — scam technique hai! Email pe bhejo instructions. Email kya hai?",
            "Bhatija IT engineer hai — verify karega. Aapka email, phone number, aur LinkedIn profile do usse!",
        ],
        "late": [
            "Computer start ho raha hai slow. 20 min lagega. Phone number aur email do — ready hote hi contact karunga!",
            "Pota aa raha hai 30 min mein. Number, email, aur company address do — verify karega sab!",
        ],
    },

    "loan_scam": {
        "early": [
            "Pre-approved loan? Apply nahi kiya! Details kahan se aaye? Bank name, employee ID, aur official email batao!",
            "Zero interest? Koi bank nahi deta — fraud hai! Company registration, RBI license, aur email do!",
            "Processing fee upfront? Loan scams advance fee maangte hain! Company GST, email, aur phone do!",
        ],
        "middle": [
            "Processing fee pay karunga. UPI ID ya bank account with IFSC batao. Email do sanction letter ke liye!",
            "Beta banker hai verify karega. DSA code, branch IFSC, company email, aur direct mobile number dijiye!",
        ],
        "late": [
            "Fee ready hai. Full bank account, IFSC, beneficiary name, aur email do — beta transfer karega!",
            "NEFT initiated! Bank ko beneficiary email chahiye. Email, phone, aur branch address do confirmation ke liye!",
        ],
    },

    "romance_scam": {
        "early": [
            "Aap kaun ho?! Main jaanta nahi! Number kahan se mila? Asli naam, photo, email, aur address batao!",
            "Army officer abroad? Real officers paisa nahi maangte! Battalion, rank, service ID, aur email kya hai?",
            "Beta phone check karta hai. Full identity do — Aadhaar photo, email, phone number, aur current address!",
        ],
        "middle": [
            "Medical emergency? Kitna chahiye? Hospital name, doctor ka phone, aapka email, aur payment UPI ID do!",
            "Customs fee? Aap pay karo! Customs office phone, aapka email, AWB number, aur payment account do!",
        ],
        "late": [
            "Paisa ready par pension 1 tarikh ko aayegi. Phone number, email, aur full bank account details do transfer ke liye!",
            "Transfer kiya par bounce hua! Sahi account number, IFSC, beneficiary name, aur email do — phir bhejunga!",
        ],
    },

    "job_scam": {
        "early": [
            "Job offer? Main retired hoon! Apply nahi kiya! Company name, website, email, aur phone number kya hai?",
            "50,000 work from home? Beta bolta hai pyramid scheme hai! Company registration, GST, aur official email do!",
            "Registration fee? Real companies charge nahi karte! Company PAN, email, aur office address batao!",
        ],
        "middle": [
            "Register karunga. Company website, incorporation number, email, aur direct phone number dijiye!",
            "Fee pay karunga. UPI ID ya bank account with IFSC do. Email bhi do resume bhejne ke liye!",
        ],
        "late": [
            "Fee arrange kiya hai. Bank account, IFSC, branch, beneficiary name, aur email do receipt ke liye!",
            "Pota office visit karega. Full address, contact number, hours, aur email do appointment ke liye!",
        ],
    },

    "insurance_scam": {
        "early": [
            "Insurance bonus? Kaun si policy? Agent license number, company email, aur phone number dijiye verify ke liye!",
            "Policy mature? Maturity date toh next year hai! Suspicious hai! IRDA code, email, aur office phone do!",
            "Premium refund? Claim number, company ka official email, aur toll-free number do verify karne ke liye!",
        ],
        "middle": [
            "Processing fee ke liye UPI ID kya hai? Company email bhi do records ke liye. Agent license number bhi!",
            "LIC agent se check karunga. Aapka naam, license number, company email, aur direct phone dijiye!",
        ],
        "late": [
            "LIC branch ja raha hoon kal. Branch address, phone, aur email bhi do policy copy bhejne ke liye!",
            "Fee ready — bank account, IFSC, beneficiary name, aur email do. Beta transfer karega!",
        ],
    },

    "payment_request": {
        "early": [
            "Paisa kyun bhejoon? Kisko? Full name, UPI ID, aur email do reason ke saath proof bhejne ke liye!",
            "Urgent UPI? UPI scams bahut common hain! Naam, phone, email, aur kyun pay karoon — sab batao!",
            "Refundable deposit? Scam excuse hai! Office address, email, aur phone number bhejo verify ke liye!",
        ],
        "middle": [
            "PhonePe khol liya. UPI ID kya hai? Receipt chahiye — email aur phone number do confirmation ke liye!",
            "NEFT karunga. Bank account, IFSC, beneficiary name, branch bhi batao. Email do receipt ke liye!",
            "Wife sab handle karti hai. Full name, UPI ID, phone number, aur email do — woh verify karegi!",
        ],
        "late": [
            "Bhej diya! Pending hai. WhatsApp number aur email do — screenshot bhejta hoon. Check karo!",
            "Daily limit ho gaya! Kal NEFT karunga. Bank account, IFSC, beneficiary name, aur email do!",
        ],
    },

    "general": {
        "early": [
            "Kaun bol raha hai? Samajh nahi aaya! Aapka naam, company, official email, aur phone number batao!",
            "Kya baat hai ji? Retired hoon, koi pending nahi! Aapka naam, email, aur phone do pehle!",
            "Thoda clearly batao! Confused ho gaya! Full naam, email, aur callback number dijiye!",
            "Wife pooch rahi hai kaun hai. Full naam, company, phone, aur email batao clearly!",
            "Hearing weak hai meri. Email pe likho — clear padhunga. Email aur phone number kya hai?",
        ],
        "middle": [
            "Samajh gaya ab. Par verify karna padega. Office address, supervisor ka phone, aur official email bhejo!",
            "Cooperate karunga ji. Par pehle — employee ID, department, aur email? Beta cross-check karega!",
            "Sab likh raha hoon. Reference number, phone, email, aur manager ka full naam kya hai?",
            "Help karna chahta hoon par risky hai. Phone number, email, aur LinkedIn profile do!",
            "Writing mein chahiye sab. Email pe bhejo. Official email aur case reference number kya hai?",
        ],
        "late": [
            "Kaam kar raha hoon uspe! Par time lagega. Callback number, email, aur WhatsApp do — 30 min mein contact karunga!",
            "Phone ki battery khatam! Email, WhatsApp, aur office address do — landline se contact karunga!",
            "Kal tak time do. Beta aur lawyer se baat karni hai. Phone, email, aur office address do!",
            "Padosi uncle retired bank manager hain. Woh baat karenge. Phone number, email, aur branch details do!",
        ],
    },
}

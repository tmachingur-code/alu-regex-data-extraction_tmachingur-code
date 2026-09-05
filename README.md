# Data Extraction & Secure Validation

## About

This project is a Python program that extracts structured data from raw text using regular expressions. I built it to practice extracting information while also making sure that invalid or potentially unsafe input is not automatically trusted.

The program extracts four types of data:

* Email addresses
* URLs
* Phone numbers
* Credit card numbers

It also validates the three required ALU email domains:

* `@alueducation.com`
* `@alumni.alueducation.com`
* `@si.alueducation.com`

## Project Structure

```text
alu-regex-data-extraction_tmachingur-code/
├── input/
│   └── raw-text.txt
├── src/
│   └── main.py
├── output/
│   └── sample-output.json
└── README.md
```

## How It Works

The program reads the raw text, uses regex to find possible matches, and then validates them before accepting them.

For security, the input is treated as untrusted. The program rejects malformed values and checks for suspicious content such as script tags, dangerous URL schemes and common injection patterns.

Credit card numbers are also checked using the Luhn algorithm. Emails and credit card numbers are masked in the output to avoid exposing sensitive information.

## Running the Program

From the project folder, run:

```bash
python src/main.py
```

The results are displayed in the terminal and saved to:

```text
output/sample-output.json
```

## What I Learned

This project helped me understand that finding a pattern with regex is not enough. The extracted data still needs to be validated, especially when it comes from an external source. I also learned the importance of protecting sensitive information when processing data.

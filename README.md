# Typescript Mongoose Boilerplate

## Folder Structure

```

Main Folder
└───Config
    └───index.js # Call all config Variable
    └───logger.js # Log handler
└───src
    │   server.js         # Application entry point
    └───Controller
        └───index.js  # Call all controller in one file
        └───user.controller.js # user all controller/Logic
    └───Database
        └───index.js # Database Config
    └───Middleware
        └───index.js # All Middleware call from this file
        └───Authentication.Middleware.js # Authentication middleware
        └───Error.Middleware.js # Error Middleware
    └───Models
        └───index.js # All Models call from this file
        └───user.model.js # User Model Config
    └───Routes
        └───index.js # All Routes call from this file
        └───user.Routes.js # All User Routes
        └───user.Authentication.js # All User Authentication Routes
    └───Utils/Services
        └───index.js # All Services call from this file
        └───APIFeature.service.js # Search, Pagination, Filter API
        └───SendEmail.service.js # Mail Config File
        └───SendToken.service.js # Token Config File
        └───ErrorHandler.service.js # Whole Error Handler
└───config.env # Secret environment Variables
```

## Getting Started

### Step 1: Set up the Development Environment

You need to set up your development environment before you can do anything.

Install [Node.js and NPM](https://nodejs.org/en/download/)

- on OSX use [homebrew](http://brew.sh) `brew install node`
- on Windows use [chocolatey](https://chocolatey.org/) `choco install nodejs`

### Step 2:- Download VSCode

Download [VSCode](https://code.visualstudio.com/)

### Step 3: Configuration & Install Packages

### Internally Install

- Install all dependencies with `yarn install`

### Running in dev mode

- Run `yarn start`
- The server address will be displayed to you as `http://0.0.0.0:3000`

### Externally Install

- After this you need to install some package in your project file

```TypeScript

yarn add bcrypt@5.0.1 body-parser@1.19.1 cloudinary@1.28.1 cookie-parser@1.4.6 cors@2.8.5 dayjs@1.10.7 dotenv@16.0.0 express@4.17.2 joi@17.6.0 jsonwebtoken@8.5.1 mongoose@6.2.1 nodemailer@6.7.2 pino@7.6.5 pino-pretty@7.5.1 consola@2.15.3

```

> Note:- You Doesn't have to mention Version for all package but for industry level its good to download package with version

## Package Information

- [bcrypt](https://www.npmjs.com/package/bcrypt)
- [body-parser](https://www.npmjs.com/package/body-parser)
- [cloudinary](https://www.npmjs.com/package/cloudinary)
- [cookie-parser](https://www.npmjs.com/package/cookie-parser)
- [cors](https://www.npmjs.com/package/cors)
- [dayjs](https://www.npmjs.com/package/dayjs)
- [dotenv](https://www.npmjs.com/package/dotenv)
- [express](https://www.npmjs.com/package/express)
- [joi](https://www.npmjs.com/package/joi)
- [jsonwebtoken](https://www.npmjs.com/package/jsonwebtoken)
- [mongoose](https://www.npmjs.com/package/mongoose)
- [nodemailer](https://www.npmjs.com/package/nodemailer)
- [consola](https://www.npmjs.com/package/consola)

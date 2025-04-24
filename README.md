# KPI Dashboard

A web-based KPI (Key Performance Indicator) tracking and management platform built with Flask and MongoDB. This application allows organizations to track, manage, and visualize their KPIs while providing role-based access control.

## Features

- **User Management**
  - Role-based access control (Admin and Regular users)
  - Secure authentication system
  - User registration and login

- **Program Management**
  - Create, view, edit, and delete programs
  - Organize KPIs by programs
  - Restricted to admin users

- **KPI Management**
  - Create and manage KPIs with detailed information
  - Track KPI progress and history
  - Attach files and comments to KPIs
  - Filter and sort KPIs by various criteria

- **Dashboard**
  - Visual representation of KPI data
  - Real-time updates
  - Customizable views

## Prerequisites

- Python 3.8 or higher
- MongoDB 4.4 or higher
- pip (Python package manager)

## Installation

1. Clone the repository:
   ```bash
   git clone [repository-url]
   cd kpi-dashboard
   ```

2. Install required packages:
   ```bash
   pip install -r requirements.txt
   ```

3. Create a `.env` file in the project root directory with the following environment variables:
   ```
   SECRET_KEY=your-secret-key-here
   MONGO_URI=mongodb://localhost:27017/
   MONGO_DB=kpi_dashboard
   ADMIN_EMAIL=admin@company.com
   ADMIN_PASSWORD=your-secure-password
   ```
   Replace the placeholder values with your secure credentials.

4. Initialize the database:
   ```bash
   python init_db.py
   ```

5. Start the application:
   ```bash
   python app.py
   ```

## Security Considerations

- The application uses secure password hashing with bcrypt
- Environment variables are used for sensitive configuration
- Role-based access control prevents unauthorized access
- Session management ensures secure user sessions
- Input validation and sanitization prevent common web vulnerabilities

## Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| SECRET_KEY | Flask secret key for session management | `your-secret-key-here` |
| MONGO_URI | MongoDB connection string | `mongodb://localhost:27017/` |
| MONGO_DB | MongoDB database name | `kpi_dashboard` |
| ADMIN_EMAIL | Admin user email | `admin@company.com` |
| ADMIN_PASSWORD | Admin user password | `your-secure-password` |

## Usage

1. **First-time Setup**
   - The system automatically creates an admin user using the credentials from the `.env` file
   - Log in with the admin credentials to access the admin dashboard

2. **Program Management**
   - Access the Programs page from the admin dashboard
   - Create new programs that will contain related KPIs
   - Edit or delete existing programs as needed

3. **KPI Management**
   - Create new KPIs and assign them to programs
   - Update KPI progress and status
   - Add comments and attachments to KPIs
   - Filter and sort KPIs based on various criteria

4. **User Management**
   - Admin users can manage other users
   - Create new user accounts
   - Assign or modify user roles

## Contributing

Please read CONTRIBUTING.md for details on our code of conduct and the process for submitting pull requests.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
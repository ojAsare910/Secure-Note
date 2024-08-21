# Web Security Fundamental

## Secure Notes App
This project implements a comprehensive backend service system for managing users and notes. It incorporates robust security features for user authentication and role-based authorization alongside CRUD operations for user and note management.

## Features
- **User Registration and Authentication**: Secure user registration and login process.
- **Role-based Authorization**: Different access controls based on user roles.
- **CRUD Operations on Notes**: Allows users to create, read, update, and delete notes.

## Technologies
- **Java**: The backend is implemented using Java, ensuring strong type-checking and object-oriented benefits.
- **Spring Boot**: Simplifies the setup and development of new Spring applications.
- **Spring Security**: Handles authentication and authorization in a comprehensive manner.

## Project Structure
- `SecurityConfig.java`: Configures security settings including URL route protections and HTTP security.
- `UserService.java`: Interface for defining user-related operations such as find, save, and update.
- `NoteService.java`: Interface for managing CRUD operations related to notes.
- `UserServiceImpl.java`: Implements the UserService interface, detailing the logic for user operations.
- `NoteServiceImpl.java`: Implements the NoteService interface, providing the logic for handling notes.
- `User.java`: Domain model for a user that includes properties like username, password, and roles.
- `Role.java`: Domain model for roles that includes properties such as role name.
- `Note.java`: Domain model for notes with properties like title, content, and creation date.
- `AppRole.java`: Enum that lists all possible user roles within the system.
- `NoteController.java`: Rest Controller that manages HTTP requests related to notes operations.
- `AdminController.java`: Rest Controller that manages HTTP requests for admin-specific operations.

## Getting Started

### Prerequisites
- **JDK 21**: Required to run the application.
- **Maven**: Used for project dependency and build management.

### Installation
1. **Clone the Repository**
   ```bash
   git clone https://github.com/ojAsare910/Secure-Note.git


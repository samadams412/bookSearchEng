const { AuthenticationError } = require("apollo-server-express");
const { User } = require("../models");
const { signToken } = require("../utils/auth");

const resolvers = {
  Query: {
    // me requires 3 parameters parent, args, context in that order
    me: async (parent, args, context) => {
      // If context has a `user` property, that means the user executing this query has a valid JWT and is logged in
      if (context.user) {
        const userData = await User.findOne({ _id: context.user._id })
          .select("-__v -password")
          .populate("books");

        return userData;
      }

      throw new AuthenticationError("Not logged in");
    },
  },

  Mutation: {
    // Creates a single user and creates a jwt token for that user
    // wrapped in try catch block
    addUser: async (parent, args) => {
      try {
        // First we create the user
        const user = await User.create(args);

        //sign a JWT and log the user in
        const token = signToken(user);

        // Return an `Auth` object that consists of the signed token and user's information
        return { token, user };
      } catch (err) {
        console.log(err);
      }
    },

    // A login mutation finds a specific user by email in the db
    login: async (parent, { email, password }) => {
      // Look up the user by the provided email address. Since the `email` field is unique, we know that only one person will exist with that email
      const user = await User.findOne({ email });

      // If there is no user with that email address, return an Authentication error stating so
      if (!user) {
        throw new AuthenticationError("Incorrect credentials");
      }

      // If there is a user found, execute the `isCorrectPassword` instance method and check if the correct password was provided
      const correctPw = await user.isCorrectPassword(password);

      // If the password is incorrect, return an Authentication error stating so
      if (!correctPw) {
        throw new AuthenticationError("Incorrect credentials");
      }

      // if correct credentials sign user in using token
      const token = signToken(user);

      return { token, user };
    },

    // add context to retrieve the logged in user without searching for them specifically
    saveBook: async (parent, args, context) => {
      // If context has a `user` property, that means the user executing this mutation has a valid JWT and is logged in
      if (context.user) {
        const updatedUser = await User.findOneAndUpdate(
          { _id: context.user._id },
          // Pushes a book to an array of books associated with this user
          { $addToSet: { savedBooks: args.input } },
          { new: true, runValidators: true }
        );
        //returns the updatedUser
        return updatedUser;
      }

      // if user is not logged in
      throw new AuthenticationError("You need to be logged in!");
    },

    removeBook: async (parent, args, context) => {
      if (context.user) {
        const updatedUser = await User.findOneAndUpdate(
          { _id: context.user._id },
          { $pull: { savedBooks: { bookId: args.bookId } } },

          { new: true }
        );

        return updatedUser;
      }
      throw new AuthenticationError("Please login in!");
    },
  },
};

module.exports = resolvers;

<?php

namespace App\Http\Controllers\auth;

use App\Exceptions\CustomHandler;
use App\Http\Controllers\Controller;
use App\Models\User;
use App\Translations\Es\AuthMessages;
use Illuminate\Database\QueryException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\Rules\Password;
use Illuminate\Validation\ValidationException;

/**
 *  Hi! This is a comment to helping you to understand better this complex code
 *  --
 *  First of all, you should to know that this is an amateur project that integrates good code
 *  practices with the purpose of save time at the moment of write code. I created some helper classes
 *  to automatize processes as 'Exceptions' or 'Try-catch code blocks'. You'll find it throughout this code.
 *  --
 *  Thanks! :)
 */

class UserAuthController extends Controller
{

  /**
   * Register method
   * --
   * Purpose
   *  Store a newly created user in a_core_users.'users'.
   * --
   * How is this method built?
   *  Throughout this project, you'll always find the next method parts: proccess, CustomHandler.
   *  I created a custom method to handle all the 'Exceptions' of a request without repeat the same
   *  boring 'Try-catch code block'. So, you only have to focus on the main problem and solve it.
   *  E.g., to register a newly user you have to validate the data before send it to the model. Create
   *  a process function that is charge of this logic and then pass it to the CustomHandler() using the
   *  needed static method as the first argument. If your function needs to use a request, 
   *  pass it as last argument. This method is going to handle all the Exceptions for you. :)
   * --
   * Extra
   *  You can custom your error validation messages with the class AuthMessages() and its 
   *  getGenericMessages() method.
   * 
   * @param  \Illuminate\Http\Request  $request
   * @return \Illuminate\Http\Response
   */
  public function register(Request $request)
  {
    // This is the main function where you need to put all your main logic.
    $processFunction = function ($req) {

      // Validation rules array. 
      $rulesValidator = [
        'name' => 'required|string',
        'email' => [
          'required',
          'email',
          'regex:/^.+@.+\..+$/i',
          'unique:users,email',
        ],
        'password' => [
          'required',
          'min:8',
          Password::min(8)
            ->letters()
            ->mixedCase()
            ->numbers()
            ->symbols(),
        ]
      ];

      // Data Validation. User three args: data_to_analize, validation_rules, custom_messages.
      $userValidator = Validator::make($req->all(), $rulesValidator, AuthMessages::getGenericMessages());

      // Validation control
      if (!$userValidator->fails()) { // <- fails() return true if the validation is incorrect, otherwise is false.

        // Store the validated data to use it later.
        $validatedData = $userValidator->validated();

        // Create a newly user using the validated data.
        User::create([
          'name' => $validatedData['name'],
          'email' => $validatedData['email'],
          'password' => Hash::make($validatedData['password']),
        ]);

        // Server response
        return response()->json([
          'message' => 'El usuario ha sido creado éxitosamente',
          'data' => [
            'name' => $validatedData['name'],
            'email' => $validatedData['email'],
            'password' => $validatedData['password'],
          ],
          'status' => 'ok'
        ], 200);
      } else {
        // Show the errors in case of the validation fails.
        throw new ValidationException($userValidator);
      }
    };

    // CustomHandler() and its class ValidationHandler($mainLogic, $request?)
    return CustomHandler::ValidationHandler($processFunction, $request);
  }

  // Login Method
  public function login(Request $request)
  {
    // This is the main function where you need to put all your main logic.
    $processFunction = function ($req) {

      // Validation rules array. 
      $rulesValidator = [
        'email' => [
          'required',
          'regex:/^.+@.+\..+$/i',
        ],
        'password' => [
          'required',
          'min:8',
        ]
      ];

      // Data Validation. User three args: data_to_analize, validation_rules, custom_messages.
      $userValidator = Validator::make($req->all(), $rulesValidator, AuthMessages::getGenericMessages());

      // Store the validated data to use it later.
      $validatedData = $userValidator->validated();

      // Validation control
      if (!$userValidator->fails()) { // <- fails() return true if the validation is incorrect, otherwise is false.

        // The first step of the user validation is verify if the email exists in the storage.
        $user = User::where('email', $validatedData['email'])->first();

        // Email validation control
        if (!$user) { // <- $user has the result of the previous email validation

          // If the email user doesn't exist, return a 'Unauthorized.401' error code
          return response()->json([
            'message' => 'Credenciales incorrectas.',
            'status' => false
          ], 401);
        } else {

          // If the email user exists, continue with the password validation. 
          $passwordValidator = Hash::check($validatedData['password'], $user->password); // <- Hash::check has two args to compare: (inputPassword, passwordFound)

          // If the email user or password user doesn't match with the current stored password, returns an 'Unauthorized.401' response 
          if (!$user || !$passwordValidator) {
            return response()->json([
              'message' => 'Credenciales incorrectas.',
              'status' => false
            ], 401);
          } else {
            // If the input password match with the stored user password, continues with the token creation
            $token = $user->createToken($user->name . '-AuthToken')->plainTextToken;
            
            // Finally, returns the token that you can use to access to the app actions.
            return response()->json([
              'message' => 'Usuario correctamente verificado.',
              'access_token' => $token,
            ]);
          }
        }
      } else {
        // Show the errors in case of the validation fails.
        throw new ValidationException($userValidator);
      }
    };

    // CustomHandler() and its class ValidationHandler($mainLogic, $request?)
    return CustomHandler::ValidationHandler($processFunction, $request);
    
  }

}

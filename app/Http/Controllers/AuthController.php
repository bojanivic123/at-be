<?php

namespace App\Http\Controllers;

use App\Http\Requests\LoginRequest;
use App\Http\Requests\RegisterRequest;
use App\Http\Resources\UserResource;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    public function register(RegisterRequest $registerRequest)
    {
        $data = $registerRequest->validated();

        $user = User::create([
            "first_name" => $data["first_name"],
            "last_name" => $data["last_name"],
            "email" => $data["email"],
            "password" => $data["password"]  
        ]);

        $token = $user->createToken("auth_token")->plainTextToken;
        return response()->json([
            "user" => new UserResource($user),
            "token" => $token 
        ]);
    }

    public function login(LoginRequest $loginRequest)
    {
        $data = $loginRequest->validated();

        $user = User::where("email", $data["email"])->first();
        if (!$user || !Hash::check($data["password"], $user->password)) {
            return response()->json([
                "message" => "Invalid credentials!"
            ], 401);
        }

        $token = $user->createToken("auth_token")->plainTextToken;
        return response()->json([
            "user" => new UserResource($user),
            "token" => $token 
        ]);
    }

    public function logout(Request $request)
    {
        $request->user()->currentAccessToken()->delete();
        $cookie = cookie()->forget("token");

        return response()->json([
            "message" => "Logged out successfully."
        ])->withCookie($cookie);
    }
}





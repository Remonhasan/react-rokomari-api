<?php

namespace App\Http\Controllers;

use App\Models\User;
use Firebase\JWT\JWT;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Auth;

class UserController extends Controller
{
    public function register(Request $request)
    {
        $user = new User();
        $user->name = $request->name;
        $user->email = $request->email;
        $user->password = Hash::make($request->password);
        $user->save();

        return $user;
    }

    public function allUser()
    {
        $users = User::all();
        return $users;
    }

    public function login(Request $request)
    {
        $email = $request->input('email');
        $password = $request->input('password');

        // Your login logic here to authenticate the user
        $user = User::where('email', $email)->first();

        if ($user && Hash::check($password, $user->password)) {
            // User authenticated successfully

            // Generate JWT
            $key = base64_encode(random_bytes(32)); // 32 bytes (256 bits) for HS256 algorithm
            
            $payload = [
                'user_id' => $user->id,
                'email' => $user->email,
            ];

            $algorithm = 'HS256'; // desired algorithm (e.g., HS256)

            $token = JWT::encode($payload, $key, $algorithm);

            return response()->json(['token' => $token], 200);
        }

        return response()->json(['message' => 'Unauthorized'], 401);
    }
}

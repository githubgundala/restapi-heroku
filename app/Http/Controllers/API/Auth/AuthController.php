<?php

namespace App\Http\Controllers\API\Auth;

use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use App\Repositories\UserRepository;
use Illuminate\Support\Facades\Hash;
use App\Http\Controllers\AppBaseController;

class AuthController extends AppBaseController
{
     /** @var  UserRepository */
     private $userRepository;

     public function __construct(UserRepository $userRepo)
     {
         $this->userRepository = $userRepo;
     }

    public function login(Request $request)
    {
        $request->validate([
            'email' => 'required|email',
            'password' => 'required|min:6|regex:"(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}"',
        ]);


        $user = $this->userRepository->allQuery(['email' => $request->email]);
        $user = $user->first();
        if (! $user || ! Hash::check($request->password, $user->password)) {
            return $this->sendError('The provided credentials are incorrect.');
        }

        $user->access_token = $user->createToken('token-auth')->plainTextToken;
        return $this->sendResponse($user->toArray(), 'User saved successfully');
    }
}

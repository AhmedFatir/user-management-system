import React from "react";
import ReactDOM from "react-dom/client";
import DashBoard from "./pages/Dashboard/DashBoard";
import Profil from "./pages/Profil/Profil";
import Game from "./pages/Game/Game";
import Chat from "./pages/Chat/Chat";
import Tournament from "./pages/Tournament/Tournament";
import LeaderBoard from "./pages/LeaderBoard/LeaderBoard";
import Setting from "./pages/Setting/Setting";
import Bot from "./pages/PingPongGame/Bot/Bot";
import Random from "./pages/PingPongGame/Random/Random";
import LocalGame from "./pages/PingPongGame/LocalGame/LocalGame";
import { createBrowserRouter, Outlet, RouterProvider } from "react-router-dom";
import Auth from "./pages/Auth/Auth";
import { AuthProvider } from "./context/Auth/AuthProvider";
import ProtectedRoutes from "./components/ProtectedRoutes/ProtectedRoutes";
import PersistLogin from "./components/PersistLogin/PersistLogin";
import OauthTwo from "./components/OauthTwo/OauthTwo";
import { NotificationProvider } from "./components/Notification/NotificationContext";
import AppLayout from "./App";
import RealTimeProvider from "./context/RealTimeProvider";
import { SocketClientProvider } from "./pages/Chat/usehooks/ChatContext";
import { BlockPopUpProvider } from "./pages/Chat/usehooks/ChatContext";
import { CurrentUserProvider } from "./pages/Chat/usehooks/ChatContext";
import Invite from './pages/PingPongGame/Invite/Invite';
import { UserProvider } from "./context/UserContext";
import { ProfileProvider } from "./context/ProfilContext";
import ProfileProviderWrapper from './context/ProfileProviderWrapper'
import TournamentGame from "./pages/PingPongGame/TournamentGame.js/TournamentGame";
import { InviteGameReconnection } from "./pages/PingPongGame/Invite/Invite";
import LocalGameTournament from "./pages/PingPongGame/LocalGame/LocalGameTournament";
import NotFound from "./pages/ErrorPages/404";
import ServerError from "./pages/ErrorPages/500";


const routes = [
  {
    element: <OauthTwo />,
    path: "/42_api",
  },
  {
    element: <PersistLogin />,
    children: [
      {
        element: <Auth />,
        path: "/auth",
      },
      {
        element: <ProtectedRoutes />,
        children: [
          {
            element:     
                  <UserProvider>
                    <RealTimeProvider>
                      <SocketClientProvider>
                          <ProfileProviderWrapper>
                              <AppLayout />
                          </ProfileProviderWrapper>
                      </SocketClientProvider>
                    </RealTimeProvider>
                  </UserProvider>,
            children: [
              { path: "/", element: <DashBoard /> },
              { path: "game", element: <Game /> },
              { path: "chat", element: <CurrentUserProvider> 
                                              <BlockPopUpProvider >
                                                        <Chat />
                                              </BlockPopUpProvider>
                                       </CurrentUserProvider> },
              { path: "tournament", element: <Tournament /> },
              { path: "leaderboard", element: <LeaderBoard /> },
              { path: "setting", element: <Setting /> },
              { path: "/user/:nameOfUser", element:
                                            
                                                <Profil /> 
                                            },
            ],
          },
        ],
      },
    ],
  },
  {path: 'bot-game', element: <Bot />},
  {path: 'local-game', element: <LocalGame />},
  {path: 'random-game', element: <Random/>},
  {path: 'invite-game', element: <Invite/>},
  {path: 'tournament-game', element: <TournamentGame/>},
  {path: 'local-tournament-game', element: <LocalGameTournament/>},
  {path: 'invite-game-reconnection', element: <InviteGameReconnection/>},
  { path: "*", element: <NotFound /> },
  { path: "/server-error", element: <ServerError /> },
];

const router = createBrowserRouter(routes);

const root = ReactDOM.createRoot(document.getElementById("root"));
root.render(
  <AuthProvider>
          <RouterProvider router={router} />
  </AuthProvider>
);

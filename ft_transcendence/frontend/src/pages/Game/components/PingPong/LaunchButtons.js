import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import ErrorModal from "./ErrorModal";
import PlayerSelection from "./PlayerSelection";
import Loading from "../../../PingPongGame/components/Loading";
import useAuth from "../../../../hooks/useAuth";
import useFetch from "../../../../hooks/useFetch";
import axios from "axios";
import CreatLocalPlayer from "./CreateLocalPlayer";
const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;

const LaunchButtons = ({ selectedMode, selectedBackground, selectedKeys, selectedPaddle ,className, onLaunch }) => {
    const [showModal, setShowModal] = useState(false);
    const [showPlayerSelection, setShowPlayerSelection] = useState(false);
    const [isLoading, setIsLoading] = useState(false);
    const navigate = useNavigate();
    const { auth } = useAuth();
    const [localPlayerUsername, setLocalPlayerUsername] = useState("");
    const [localPlayerAvatar, setLocalPlayerAvatar] = useState(null);
    const [showCreateLocalPlayer, setShowCreateLocalPlayer] = useState(false);
    const { data: currentUser } = useFetch(`${BACKEND_URL}/user/stats`);
    const [opponentKeys, setOpponentKeys] = useState("");

    useEffect(() => {
        const handleOpponentKeys = () => {
            if (selectedKeys === "up-down") {
                setOpponentKeys("ws");
            } else {
                setOpponentKeys("up-down");
            }
    
        }
        handleOpponentKeys();
    }, selectedKeys)

    const checkInviteRoom = async () => {
        setIsLoading(true);
        try {
            const response = await axios.get(`${BACKEND_URL}/api/game/check-invite-room`, {
                headers: {
                    'Content-Type' : 'application/json',
                    'Authorization': `Bearer ${auth.accessToken}`,
                }
            });
            setIsLoading(false);
            return response.data;
        } catch (error) {
            console.error("Failed to check invite room:", error);
            setIsLoading(false);
            return { exists: false };
        }
    };

    const handleLaunchGame = async () => {
        onLaunch();
        if (!selectedBackground || !selectedKeys) {
            setShowModal(true);
            return;
        }

        setIsLoading(true);
        setTimeout(async () => {
            setIsLoading(false);
            if (selectedMode === 'Invite') {
                const check = await checkInviteRoom();
                if (check.exists) {
                    navigate("/invite-game-reconnection");
                } else {
                    setShowPlayerSelection(true);
                }
            } else if (selectedMode === 'Pongy!') {
                navigate("/bot-game");
            } else if (selectedMode === 'Local') {
                setShowCreateLocalPlayer(true);
            } else if (selectedMode === 'Random') {
                navigate("/random-game");
            }
        }, 1000);
    };

    const closeModal = () => {
        setShowModal(false);
    };

    const handlePlayerSelect = () => {
        setShowPlayerSelection(false);
    };

    const handleCreateLocalPlayer = async (username, avatar, paddle) => {
        try {
            const opponentResponse = await axios.post(`${BACKEND_URL}/user/create-local-player/`, 
                { 
                    username: username,
                    paddle: paddle,
                    keys: opponentKeys,
                },
                {
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${auth.accessToken}`
                    }
                }
            );
            const opponentUserId = opponentResponse.data.id
            const currentUserResponse = await axios.post(`${BACKEND_URL}/user/create-local-player/`, 
                { 
                    username: currentUser.username,
                    paddle: selectedPaddle,
                    keys: selectedKeys,
                },
                {
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${auth.accessToken}`
                    }
                }
            );
            const cuurrentUserId = currentUserResponse.data.id
            const gameRoomResponse = await axios.post(`${BACKEND_URL}/api/game/create-local-game-room/`, { 
                player1: cuurrentUserId,
                player2: opponentUserId,
                arena: selectedBackground,
            }, {
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${auth.accessToken}`
                }
            });
            const gameRoomId = gameRoomResponse.data.id;
            setShowCreateLocalPlayer(false);
            navigate('/local-game', { state: { gameRoomId: gameRoomId } }, {  replace:true } );
        } catch (error) {
            console.error("Error creating local players:", error);
            alert("Failed to create players. Please try again.");
        }
    };
    const handleCloseModal = () => {
        setShowCreateLocalPlayer(false);
    }

    return (
        <div className={className}>
            <div>
                <button onClick={handleLaunchGame} className="play-button buttons">Play</button>
                {showModal && (
                    <ErrorModal onClose={closeModal} />
                )}
                {showPlayerSelection && (
                    <PlayerSelection onPlayerSelect={handlePlayerSelect} onCancel={() => setShowPlayerSelection(false)} />
                )}
                {showCreateLocalPlayer && (
                    <CreatLocalPlayer 
                        handleCreateLocalPlayer={handleCreateLocalPlayer}
                        handleCloseModal={handleCloseModal}
                    />
                )}
            </div>
        </div>
    );
};

export default LaunchButtons;
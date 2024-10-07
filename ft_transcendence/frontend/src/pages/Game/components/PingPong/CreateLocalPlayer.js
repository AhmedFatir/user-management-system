import React, { useState } from 'react';
import { ChevronLeft, ChevronRight } from 'lucide-react';
import './CreateLocalPlayer.css';

const CreateLocalPlayer = ({ handleCreateLocalPlayer, handleCloseModal }) => {
    const [username, setUsername] = useState('');
    const [currentAvatar, setCurrentAvatar] = useState(0);
    const [currentColorIndex, setCurrentColorIndex] = useState(0);
    const [error, setError] = useState('');
    const paddleColors = ['#BC4F00', '#036145', '#8D0202', '#002194'];
    const avatars = [
        // Add avatar paths as needed
    ];

    const handlePaddleColorChange = (direction) => {
        setCurrentColorIndex((prevIndex) => {
            if (direction === 'next') {
                return (prevIndex + 1) % paddleColors.length;
            } else {
                return (prevIndex - 1 + paddleColors.length) % paddleColors.length;
            }
        });
    };

    const handleSubmit = () => {
        if (!username.trim()) {
            setError('Invalid Username');
            return;
        }
        setError('');
        handleCreateLocalPlayer(username, avatars[currentAvatar], paddleColors[currentColorIndex]);
        handleCloseModal();
    };

    const cycleAvatar = (direction) => {
        setCurrentAvatar((prev) => {
            if (direction === 'next') {
                return (prev + 1) % avatars.length;
            } else {
                return (prev - 1 + avatars.length) % avatars.length;
            }
        });
    };

    return (
        <div className="modal-overlay" onClick={handleCloseModal}>
            <div className="modal-content" onClick={(e) => e.stopPropagation()}>
                <h2 className="modal-title">Guest Part</h2>
                
                <div className="avatar-selection">
                    <button onClick={() => cycleAvatar('prev')} className="avatar-button">
                        <ChevronLeft size={24} />
                    </button>
                    <img src={avatars[currentAvatar]} alt="Avatar" className="avatar-image" />
                    <button onClick={() => cycleAvatar('next')} className="avatar-button">
                        <ChevronRight size={24} />
                    </button>
                </div>
                <h2>PADDLE</h2>
                <div className="paddle-colors-container1">
                    <button onClick={() => handlePaddleColorChange('prev')} className="avatar-button">
                        <ChevronLeft size={24} />
                    </button>
                    <div className="paddle-color-preview1" style={{ backgroundColor: paddleColors[currentColorIndex] }} />
                    <button onClick={() => handlePaddleColorChange('next')} className="avatar-button">
                        <ChevronRight size={24} />
                    </button>
                </div>
                <input
                    type="text"
                    placeholder="Username"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    className="username-input"
                />
                {error && <p className="error-message">{error}</p>}
                
                <button
                    onClick={handleSubmit}
                    className="submit-button"
                >
                    Submit
                </button>
            </div>
        </div>
    );
};

export default CreateLocalPlayer;
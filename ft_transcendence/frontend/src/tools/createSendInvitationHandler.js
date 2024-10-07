import axios from 'axios';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;

export const createSendInvitationHandler = (auth) => {
  return async (opponentId) => {
    const notification = {
      player_receiver_id: opponentId,
    };

    try {
      const response = await axios.post(
        `${BACKEND_URL}/api/game/send-challenge/`,
        notification,
        {
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${auth.accessToken}`,
          }
        }
      );
      console.log("Invitation sent successfully", response.data);
      return response.data;
    } catch (error) {
      console.error("Failed to send invitation", error);
      throw error;
    }
  };
};
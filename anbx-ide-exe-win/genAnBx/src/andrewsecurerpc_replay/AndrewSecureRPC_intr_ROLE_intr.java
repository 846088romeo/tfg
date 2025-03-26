package andrewsecurerpc_intr;

import anbxj.AnBx_Debug;
import anbxj.AnBx_Layers;
import anbxj.AnBx_Params;
import anbxj.AnB_Protocol;
import anbxj.AnB_Session;

import java.util.Map;
import javax.crypto.SealedObject;

public final class AndrewSecureRPC_intr_ROLE_intr extends AnB_Protocol<AndrewSecureRPC_intr_Steps, AndrewSecureRPC_intr_Roles> {

    private static long sessionID = 0;

    // Almacenar el mensaje inicial para el ataque de replay
    private AnBx_Params storedMessage = null;

    public AndrewSecureRPC_intr_ROLE_intr(AndrewSecureRPC_intr_Roles role, String name, String sharepath) {
        super();
        this.role = role;
        this.name = name;
        this.sharepath = sharepath;
        if (sessionID < Long.MAX_VALUE) {
            sessionID++;
        }
    }

    protected void init() {
        // Configuración inicial
        setAbortOnFail(false);
    }

    public void run(Map<String, AnB_Session> lbs, Map<String, String> aliases, long sessions) {

        this.aliases = aliases;
        this.lbs = lbs;
        AndrewSecureRPC_intr_ROLE_intr.sessions = sessions;

        AnB_Session ROLE_intr_channel_ROLE_A_Server_Insecure = lbs.get("ROLE_intr_channel_ROLE_A_Server_Insecure");
        AnB_Session ROLE_intr_channel_ROLE_B_Client_Insecure = lbs.get("ROLE_intr_channel_ROLE_B_Client_Insecure");

        init();

        ROLE_intr_channel_ROLE_A_Server_Insecure.Open();
        ROLE_intr_channel_ROLE_B_Client_Insecure.Open();

        do {
            AnBx_Debug.out(layer, "Session started: " + sessionID + "/" + sessions);

            try {
                // Ejecutar los pasos del protocolo
                executeStep(ROLE_intr_channel_ROLE_A_Server_Insecure, AndrewSecureRPC_intr_Steps.STEP_0);
                executeStep(ROLE_intr_channel_ROLE_B_Client_Insecure, AndrewSecureRPC_intr_Steps.STEP_1);
                executeStep(ROLE_intr_channel_ROLE_B_Client_Insecure, AndrewSecureRPC_intr_Steps.STEP_2);
                executeStep(ROLE_intr_channel_ROLE_A_Server_Insecure, AndrewSecureRPC_intr_Steps.STEP_3);
                executeStep(ROLE_intr_channel_ROLE_A_Server_Insecure, AndrewSecureRPC_intr_Steps.STEP_4);
                executeStep(ROLE_intr_channel_ROLE_B_Client_Insecure, AndrewSecureRPC_intr_Steps.STEP_5);
                executeStep(ROLE_intr_channel_ROLE_B_Client_Insecure, AndrewSecureRPC_intr_Steps.STEP_6);
                executeStep(ROLE_intr_channel_ROLE_A_Server_Insecure, AndrewSecureRPC_intr_Steps.STEP_7);

                AnBx_Debug.out(layer, "Session completed: " + sessionID + "/" + sessions);
                sessionID++;

            } catch (ClassCastException e) {
                abort("Message format type error", e, sessionID);
            } catch (NullPointerException e) {
                abort("Some data have not been properly initialised", e, sessionID);
            } catch (Exception e) {
                abort("Generic error", e, sessionID);
            }
        } while ((sessionID <= sessions && sessionID < Long.MAX_VALUE) || sessions < 0);

        ROLE_intr_channel_ROLE_A_Server_Insecure.Close();
        ROLE_intr_channel_ROLE_B_Client_Insecure.Close();
    }

    protected void executeStep(AnB_Session s, AndrewSecureRPC_intr_Steps step) {

        status(step);

        switch (step) {

            case STEP_0:
                // Interceptar el mensaje inicial de A
                noteqCheck("0.2", aliases.get("ROLE_intr"), aliases.get("ROLE_A"));
                noteqCheck("0.4", aliases.get("ROLE_intr"), aliases.get("ROLE_B"));
                AnBx_Params messageFromA = (AnBx_Params) s.Receive();
                eqCheck("0.1", aliases.get("ROLE_A"), (String) messageFromA.getValue(0));

                // Almacenar el mensaje para el ataque de replay
                storedMessage = messageFromA;

                break;

            case STEP_1:
                // Reenviar el mensaje almacenado a B (ataque de replay) con un 40% de probabilidad
				if (random.nextFloat() < 0.4 && storedMessage != null) {
					SealedObject sealedMessage = (SealedObject) storedMessage.getValue(1);
					s.Send(new AnBx_Params(aliases.get("ROLE_A"), sealedMessage));
				} else {
					// Si no hay mensaje almacenado, reenviar el mensaje actual
					SealedObject sealedMessage = (SealedObject) storedMessage.getValue(1);
					s.Send(new AnBx_Params(aliases.get("ROLE_A"), sealedMessage));
				}

                break;

            case STEP_2:
                // Interceptar la respuesta de B
                SealedObject responseFromB = (SealedObject) s.Receive();
                wffCheck("2.1", responseFromB);

                break;

            case STEP_3:
                // Reenviar la respuesta de B a A
                s.Send(responseFromB);

                break;

            case STEP_4:
                // Interceptar el siguiente mensaje de A
                SealedObject messageFromA2 = (SealedObject) s.Receive();
                wffCheck("4.1", messageFromA2);

                break;

            case STEP_5:
                // Reenviar el mensaje de A a B
                s.Send(messageFromA2);

                break;

            case STEP_6:
                // Interceptar la respuesta final de B
                SealedObject finalResponseFromB = (SealedObject) s.Receive();
                wffCheck("6.1", finalResponseFromB);

                break;

            case STEP_7:
                // Reenviar la respuesta final de B a A
                s.Send(finalResponseFromB);

                break;

            default:
                break;
        }

        status(step);
    }
}